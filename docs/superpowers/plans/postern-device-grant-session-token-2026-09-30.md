# Device Grant Layer-1 Session Token Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `POST /token` issue a layer-1 session (a 10-minute access token whose audience is the MCP server, signed by a third SESSION key, plus a rotating refresh token in a one-hour family), add the `refresh_token` grant, recall a swapped session at `POST /scan`, verify session tokens in `services/api` with a bounded JWKS cache, and take the read key out of `services/confirm`, exactly as `dev-docs/device-grant-session-token-spec.md` specifies.

**Architecture:** A pure resource-URI normalizer and a refresh-family store (both backends, one pure verdict, compare-and-set on Redis) land in `postern_core.auth`; the revocation store gains a millisecond customer-revocation stamp written by one Lua script. `services/confirm` gains `session_token.py` (the SESSION key and `SessionTokenMinter`), `/session/jwks.json`, startup refusals, the rewritten `_exchange`, the new `_refresh` grant and the recall in `_scan`. `services/api` gains `session_verifier.py`, a `JWTVerifier` subclass whose JWKS cache is bounded, and refuses a non-URI audience when customer authentication is on. No migration.

**Tech Stack:** Python 3.12, Starlette routes on the existing confirm app, FastMCP 4.0.3's `JWTVerifier`, joserfc, redis-py 5.3.1 (`WATCH`/`MULTI`, `EVAL`, `TIME`), `httpx2` ASGI and mock transports, testcontainers Postgres, Redis and Vault already started by `tests/conftest.py` and `tests/test_vault_live.py`.

**Depends on:** `origin/main` at `41a1701`, which carries the pairing-network-signal plan (`docs/superpowers/plans/postern-pairing-network-signal-2026-09-30.md`, executed and merged) and its review follow-ups (`368cc87`, `4d13cca`, `f88b857`, `41a1701`). Every replace step below was re-derived against that tree. If `main` has moved past `41a1701` in `services/confirm/device_auth.py`, `services/confirm/audit.py` or the files each task names, re-check each replace step's old text before pasting.

---

## Before you start: rules that apply to every task

1. **Work in a worktree, never on `main`.** Every commit below lands on the worktree branch. Do not push.
2. **`make ci` must exit 0 before every commit.** It needs Docker running (Postgres, Redis and Vault containers) and took four to five minutes per run while this plan was validated. The last step of every task runs it.
3. **Format with `uv run ruff format packages services tests`, never `make fmt`.** `make fmt` is unscoped and rewrites the Python code fences inside the markdown documents, this plan included.
4. **The plan file itself is scanned by `make citations`.** `tools/check_citations.py` resolves every anchored citation (the pytest node-id form and the backticked possessive form) in every tracked file. The code below names every NEW symbol with double backticks or by name, never in an anchored form, so it passes before and after each task. Keep it that way when you paste it. `uv run pytest ...` commands are exempt because `pytest` precedes the node id on the same line.
5. **No em-dashes in any prose or comment you write.** Some replace steps quote existing text that carries them; those are the tree's, not new.
6. **Paste the code as given.** Every block below was applied to a copy of the tree and passed `make ci` there (see "Validation" at the end). The comment density is already the codebase's; do not add more.
7. **A "replace" step is an exact-text substitution.** The quoted old text occurs exactly once in the file at that point in the plan. If it does not, stop: the tree has moved and the step needs re-deriving, not guessing.
8. **TDD in every task:** write the failing tests, run them and see the stated failure, implement, run them and see them pass, run `make ci`, commit. Tasks 11 and 12 add tests that pass on their first run, and each says why; Task 13 is documentation and has no test of its own.

## Verified facts this plan depends on

All measured against `41a1701` (`make ci` exit 0, 3487 passed) and the project's CPython 3.12 virtualenv, on 30 September and 1 October 2026.

- **FastMCP 4.0.3's `JWTVerifier`** (read in the installed `fastmcp/server/auth/providers/jwt.py`): the constructor sets `self._cache_ttl = 3600`; `_get_jwks_key` returns from `self._jwks_cache` only while `time.time() - self._jwks_cache_time < self._cache_ttl` and the kid is cached, and otherwise calls `_fetch_jwks`, which uses an injected `http_client` if one was passed and a fresh `httpx2.AsyncClient(timeout=10)` if not; it stamps `_jwks_cache_time` only after a fetch that returned; `load_access_token` returns `None` for any failure. `str(inspect.signature(JWTVerifier._get_jwks_key))` prints `(self, kid: 'str | None') -> 'str'`: the module uses `from __future__ import annotations`.
- **`httpx2.MockTransport` accepts an `async` handler** (its `handle_async_request` awaits a non-`Response` return), which is how the coalescing test holds a fetch open.
- **Postgres `jsonb` does not keep key order.** `audit_log.arguments` read back through SQLAlchemy is sorted, so the key-order rule of spec section 9 is pinned on `PairingAudit._arguments()`, not on a stored row.
- **`fakeredis` 2.38.0 without `lupa` answers `EVAL` with "unknown command 'eval'".** Task 4 makes `revoke_customer_client` one Lua script, so the two ZT-7 test fixtures that patched `redis.asyncio.from_url` onto a `FakeServer` move to the suite's real Redis container (`redis_url`, one key prefix per test).
- **`tools/check_citations.py` resolves two anchored citations of `JWTVerifier` in `services/api/server.py`** (from `stub/backend.py` and its own docstring), so Task 10 keeps that import and annotates the new verifier as a `JWTVerifier`.
- **`dev-docs/device-grant-session-token-spec.md` carries one anchored citation of a test Task 6 renames** (`test_an_approved_code_is_refused_503_unspent_and_recorded_as_issuance_disabled`), so Task 6 rewrites that one sentence of the spec into an unanchored form.
- **ruff's `S105`/`S106` flag any string assigned to a name containing `token`**, which includes `session_token_issuer` and `session_token_audience`; the code carries `# noqa: S105`/`S106` where the existing `write_token_issuer` does.
- **Inventory counts** (`tests/test_settings_bounds.py`): `KNOWN_ENV` 74 to 83, strings 27 to 32, `BOUNDED` 40 to 42, flags 3 to 5, reader union 47 to 51 and `names_read_by("confirm")` 58 to 67 in Task 1; confirm 67 to 63 in Task 9; `names_read_by("api")` 38 to 39 in Task 10.
- **`tests/test_vault_live.py` collects 23 tests after Task 11** (19 before it).

## File structure

Created:

| File | Responsibility |
|---|---|
| `packages/postern-core/src/postern_core/auth/resource_uri.py` | Pure: `normalize_resource`, `is_normal_https_resource` (RFC 8707 section 2, RFC 3986 sections 6.2.2.1 and 6.2.3). |
| `packages/postern-core/src/postern_core/auth/refresh_sessions.py` | `RefreshSession`, `Rotation`, `RotationOutcome`, the pure verdict, `InMemoryRefreshSessionStore`, `RedisRefreshSessionStore`, the factory, token and scope helpers. |
| `services/confirm/session_token.py` | `ACCESS_TOKEN_LIFETIME_SECONDS`, `SessionClaims`, `SessionTokenMinter`, `build_session_minter`. |
| `services/api/session_verifier.py` | `SessionTokenVerifier`, the bounded JWKS cache. |
| `tests/test_resource_uri.py`, `tests/test_session_token_settings.py`, `tests/test_session_token.py`, `tests/test_refresh_sessions.py`, `tests/test_customer_revoked_at.py`, `tests/test_session_startup_refusals.py`, `tests/test_token_session_issuance.py`, `tests/test_refresh_grant.py`, `tests/test_scan_recall.py`, `tests/test_session_verifier.py`, `tests/test_session_end_to_end.py` | One per task that adds behaviour; each file's docstring names its spec section. |

Modified:

| File | Responsibility of the change |
|---|---|
| `services/confirm/settings.py` | Nine session fields and their `from_env` reads; `check_session_token_settings`; the device-code TTL ceiling; the read-key fields removed. |
| `services/confirm/main.py` | The session minter, the family store, `/session/jwks.json`, the two startup refusals, `process_local_sessions`; the read key removed. |
| `services/confirm/device_auth.py` | `/token`'s wrapper and `resource` check, `_exchange`'s session, `_refresh_grant`/`_refresh`, the recall, the reserved `client_id`; the 503 issuance path removed. |
| `services/confirm/audit.py` | `names(session_id=)`, `recalled()`, `REFRESH_TOOL_NAME`, `RECALL_TOOL_NAME` and ten `DETAIL_*` literals; `DETAIL_ISSUANCE_DISABLED` historical. |
| `services/confirm/jwks.py`, `auth.py`, `rate_limit.py`, `revocation.py` | `session_jwks_route`; the ninth public path; its rate-limit row; the revocation stamp and `Retry-After`. |
| `packages/postern-core/src/postern_core/auth/revocation.py` | `CUSTOMER_REVOKED_AT_TTL_SECONDS`, `customer_revoked_at` on both backends, the Lua revoke script. |
| `packages/postern-core/src/postern_core/auth/device_codes.py` | `DeviceCode.session_id`; `consume_device_code(..., *, session_id)`. |
| `packages/postern-core/src/postern_core/auth/keys.py`, `vault.py`, `env_inventory.py` | Docstrings for the SESSION key; `public_key_ttl_from_env`; eleven inventory rows. |
| `services/api/server.py`, `settings.py` | `SessionTokenVerifier`, the audience refusal, `customer_jwks_ttl_seconds`, `allow_non_uri_audience`. |
| `docker-compose.yml` | A `redis` service, the session transit key and policy, `api` pointed at confirm, URI audiences. |
| Existing tests | Listed per task. |
| `CLAUDE.md`, `dev-docs/decisions/0010-...`, `0012-...`, `dev-docs/qr-page-spec.md`, `dev-docs/device-grant-session-token-spec.md`, `docs/user-guide/...`, `docs/integration/mobile-app-pairing-contract.md` | Spec section 11 and the "Docs that go stale" list. |

---

### Task 1: The resource URI rule and the session-token settings

Spec section 2's settings table and its four startup refusals, and section 5's normalization rule, as pure code. Nothing calls `check_session_token_settings` until Task 5, so no existing test changes except the inventory counts.

**Files:**
- Create: `packages/postern-core/src/postern_core/auth/resource_uri.py` (`normalize_resource`, `is_normal_https_resource`)
- Modify: `packages/postern-core/src/postern_core/env_inventory.py` (nine `INVENTORY` rows and the count comment)
- Modify: `services/confirm/settings.py` (nine `ConfirmSettings` fields, their `from_env` reads, `for_testing`'s two flags, `check_session_token_settings`)
- Create: `tests/test_resource_uri.py`
- Create: `tests/test_session_token_settings.py`
- Modify: `tests/test_settings_bounds.py` (two `Bounded` rows, `not_numeric`, the counts)

- [ ] **Step 1: Write the failing tests**

Create `tests/test_resource_uri.py` with:

```python
"""The one normal form a resource indicator is compared in.

`postern_core.auth.resource_uri` is pure, so every case the session-token
spec names for ``resource`` (host case, ``:443``, an empty path, a significant
trailing slash, a fragment, a relative reference) is checked here without an
app, and both services' refusals lean on the same two functions.
"""

from __future__ import annotations

import pytest
from postern_core.auth.resource_uri import is_normal_https_resource, normalize_resource

NORMALIZED = [
    ("https://mcp.example/mcp", "https://mcp.example/mcp"),
    ("HTTPS://MCP.Example/mcp", "https://mcp.example/mcp"),
    ("https://mcp.example:443/mcp", "https://mcp.example/mcp"),
    ("https://mcp.example:/mcp", "https://mcp.example/mcp"),
    ("https://mcp.example:8443/mcp", "https://mcp.example:8443/mcp"),
    ("http://mcp.example:80/mcp", "http://mcp.example/mcp"),
    ("https://mcp.example", "https://mcp.example/"),
    ("https://mcp.example/MCP", "https://mcp.example/MCP"),
    ("https://mcp.example/mcp/", "https://mcp.example/mcp/"),
    ("https://mcp.example/a%2Fb", "https://mcp.example/a%2Fb"),
    ("https://mcp.example/a%2fb", "https://mcp.example/a%2fb"),
    ("https://[2001:DB8::1]:443/mcp", "https://[2001:db8::1]/mcp"),
    ("https://mcp.example/mcp?x=1", "https://mcp.example/mcp?x=1"),
]


@pytest.mark.parametrize(("value", "expected"), NORMALIZED)
def test_the_normal_form(value: str, expected: str) -> None:
    assert normalize_resource(value) == expected


def test_a_trailing_slash_names_a_different_resource() -> None:
    assert normalize_resource("https://mcp.example/mcp") != normalize_resource(
        "https://mcp.example/mcp/"
    )


@pytest.mark.parametrize(
    "value",
    [
        "",
        "https://mcp.example/mcp#frag",
        "https://mcp.example/mcp#",
        "/mcp",
        "mcp.example/mcp",
        "urn:postern:mcp",
        "https://",
        "https://mcp.example:notaport/mcp",
        "https://mcp.example:99999/mcp",
    ],
)
def test_a_value_that_cannot_name_a_resource_is_none(value: str) -> None:
    assert normalize_resource(value) is None


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("https://mcp.postern.internal/mcp", True),
        ("https://mcp.example/", True),
        ("https://mcp.example", False),
        ("HTTPS://mcp.example/mcp", False),
        ("https://MCP.example/mcp", False),
        ("https://mcp.example:443/mcp", False),
        ("http://mcp.example/mcp", False),
        ("https://mcp.example/mcp#x", False),
        ("postern", False),
    ],
)
def test_is_normal_https_resource(value: str, expected: bool) -> None:
    assert is_normal_https_resource(value) is expected
```

Create `tests/test_session_token_settings.py` with:

```python
"""The session-token settings and the startup refusals of spec section 2.

`services/confirm/settings.py`'s ``check_session_token_settings`` is pure over
a settings object, so each refusal is driven here without building an app;
`create_confirm_app` calling it is pinned where the app is built.
"""

from __future__ import annotations

import logging
from dataclasses import replace

import pytest

from services.confirm.settings import ConfirmSettings, check_session_token_settings

URI_AUDIENCE = "https://mcp.postern.internal/mcp"


def _deployable(**overrides: object) -> ConfirmSettings:
    """Settings a deployment could run: a URI audience and no development flag."""
    base = replace(
        ConfirmSettings.for_testing(),
        session_token_audience=URI_AUDIENCE,
        allow_non_uri_audience=False,
        allow_process_local_sessions=False,
    )
    return replace(base, **overrides)  # type: ignore[arg-type]


def test_the_field_defaults_are_the_safe_values() -> None:
    settings = ConfirmSettings()
    assert settings.session_key_pem_path is None
    assert settings.session_key_kid == "session-1"
    assert settings.vault_session_key_name == "postern-session"
    assert settings.session_token_issuer == "https://auth.postern.internal"  # noqa: S105
    assert settings.session_token_audience == "postern"  # noqa: S105
    assert settings.allow_non_uri_audience is False
    assert settings.allow_process_local_sessions is False
    assert settings.max_refresh_sessions == 40_000
    assert settings.rate_limit_session_jwks == 300


def test_for_testing_sets_both_development_flags() -> None:
    settings = ConfirmSettings.for_testing()
    assert settings.allow_non_uri_audience is True
    assert settings.allow_process_local_sessions is True


def test_from_env_reads_every_session_variable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("POSTERN_SESSION_KEY_PEM_PATH", "/run/secrets/session.pem")
    monkeypatch.setenv("POSTERN_SESSION_KEY_KID", "session-7")
    monkeypatch.setenv("POSTERN_VAULT_SESSION_KEY_NAME", "bank-session")
    monkeypatch.setenv("POSTERN_SESSION_TOKEN_ISSUER", "https://auth.bank.example")
    monkeypatch.setenv("POSTERN_SESSION_TOKEN_AUDIENCE", "https://mcp.bank.example/mcp")
    monkeypatch.setenv("POSTERN_ALLOW_NON_URI_AUDIENCE", "true")
    monkeypatch.setenv("POSTERN_ALLOW_PROCESS_LOCAL_SESSIONS", "1")
    monkeypatch.setenv("POSTERN_MAX_REFRESH_SESSIONS", "12")
    monkeypatch.setenv("POSTERN_CONFIRM_RATE_LIMIT_SESSION_JWKS", "30")
    settings = ConfirmSettings.from_env()
    assert settings.session_key_pem_path == "/run/secrets/session.pem"
    assert settings.session_key_kid == "session-7"
    assert settings.vault_session_key_name == "bank-session"
    assert settings.session_token_issuer == "https://auth.bank.example"  # noqa: S105
    assert settings.session_token_audience == "https://mcp.bank.example/mcp"  # noqa: S105
    assert settings.allow_non_uri_audience is True
    assert settings.allow_process_local_sessions is True
    assert settings.max_refresh_sessions == 12
    assert settings.rate_limit_session_jwks == 30


def test_a_deployable_configuration_passes() -> None:
    check_session_token_settings(_deployable())


@pytest.mark.parametrize(
    "issuer",
    [
        "http://auth.bank.example",
        "https://",
        "auth.bank.example",
        "https://auth.bank.example?x=1",
        "https://auth.bank.example#x",
    ],
)
def test_an_issuer_that_is_not_an_https_url_is_refused(issuer: str) -> None:
    with pytest.raises(ValueError, match="POSTERN_SESSION_TOKEN_ISSUER") as raised:
        check_session_token_settings(_deployable(session_token_issuer=issuer))
    assert repr(issuer) in str(raised.value)


def test_an_issuer_shared_with_the_write_token_is_refused() -> None:
    settings = _deployable(session_token_issuer="https://mcp-write.internal")  # noqa: S106
    with pytest.raises(ValueError, match="POSTERN_WRITE_TOKEN_ISSUER"):
        check_session_token_settings(settings)


def test_an_issuer_shared_with_the_app_assertion_is_refused() -> None:
    settings = _deployable(session_token_issuer="https://app.postern-local-dev.invalid")  # noqa: S106
    with pytest.raises(ValueError, match="POSTERN_APP_ASSERTION_ISSUER"):
        check_session_token_settings(settings)


@pytest.mark.parametrize(
    "audience",
    [
        "postern",
        "https://mcp.postern.internal",
        "HTTPS://mcp.postern.internal/mcp",
        "https://MCP.postern.internal/mcp",
        "https://mcp.postern.internal:443/mcp",
        "https://mcp.postern.internal/mcp#x",
        "http://mcp.postern.internal/mcp",
    ],
)
def test_an_audience_not_in_normal_form_is_refused_without_the_flag(audience: str) -> None:
    with pytest.raises(ValueError, match="POSTERN_SESSION_TOKEN_AUDIENCE") as raised:
        check_session_token_settings(_deployable(session_token_audience=audience))
    assert "POSTERN_ALLOW_NON_URI_AUDIENCE" in str(raised.value)


def test_the_flag_admits_a_non_uri_audience_and_warns(caplog: pytest.LogCaptureFixture) -> None:
    settings = _deployable(session_token_audience="postern", allow_non_uri_audience=True)  # noqa: S106
    with caplog.at_level(logging.WARNING, logger="services.confirm.settings"):
        check_session_token_settings(settings)
    assert "POSTERN_ALLOW_NON_URI_AUDIENCE" in caplog.text


def test_the_flag_does_not_warn_for_a_uri_audience(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.WARNING, logger="services.confirm.settings"):
        check_session_token_settings(_deployable(allow_non_uri_audience=True))
    assert caplog.text == ""


def test_an_audience_shared_with_the_app_assertion_is_refused() -> None:
    settings = _deployable(app_assertion_audience=URI_AUDIENCE)
    with pytest.raises(ValueError, match="POSTERN_APP_ASSERTION_AUDIENCE"):
        check_session_token_settings(settings)
```

In `tests/test_settings_bounds.py`, replace:

```python
likely to be written. So the third rule keys on the one thing every spelling
shares, the variable's NAME at the read site. The swept tree names 74
``POSTERN_*`` variables in two disjoint populations: 27 read directly, all of
them strings, and 47 handed to a reader, which are `BOUNDED`'s 40,
`STORE_BOUNDED`'s 2, `VAULT_BOUNDED`'s 2 and `FLAGS`' 3. Nothing is in both,
nothing is in neither, and `TestEveryEnvironmentReadNamesAnInventoriedVariable`
```

with:

```python
likely to be written. So the third rule keys on the one thing every spelling
shares, the variable's NAME at the read site. The swept tree names 83
``POSTERN_*`` variables in two disjoint populations: 32 read directly, all of
them strings, and 51 handed to a reader, which are `BOUNDED`'s 42,
`STORE_BOUNDED`'s 2, `VAULT_BOUNDED`'s 2 and `FLAGS`' 5. Nothing is in both,
nothing is in neither, and `TestEveryEnvironmentReadNamesAnInventoriedVariable`
```

In `tests/test_settings_bounds.py`, replace:

```python
    Bounded(
        "POSTERN_MAX_SCOPES_LENGTH",
```

with:

```python
    Bounded(
        "POSTERN_MAX_REFRESH_SESSIONS",
        "max_refresh_sessions",
        "confirm",
        40_000,
        ("0", "-1"),
        ("1", "40000"),
    ),
    Bounded(
        "POSTERN_MAX_SCOPES_LENGTH",
```

In `tests/test_settings_bounds.py`, replace:

```python
    Bounded(
        "POSTERN_CONFIRM_CUSTOMER_RATE_LIMIT_SCAN",
```

with:

```python
    Bounded(
        "POSTERN_CONFIRM_RATE_LIMIT_SESSION_JWKS",
        "rate_limit_session_jwks",
        "confirm",
        300,
        ("0", "-1"),
        ("1",),
    ),
    Bounded(
        "POSTERN_CONFIRM_CUSTOMER_RATE_LIMIT_SCAN",
```

In `tests/test_settings_bounds.py`, replace:

```python
            "POSTERN_VAULT_WRITE_KEY_NAME",
        }
```

with:

```python
            "POSTERN_VAULT_WRITE_KEY_NAME",
            # The layer-1 session token's key, issuer and audience, and its two
            # development flags: strings and flags, with no range to leave.
            "POSTERN_SESSION_KEY_PEM_PATH",
            "POSTERN_SESSION_KEY_KID",
            "POSTERN_VAULT_SESSION_KEY_NAME",
            "POSTERN_SESSION_TOKEN_ISSUER",
            "POSTERN_SESSION_TOKEN_AUDIENCE",
            "POSTERN_ALLOW_NON_URI_AUDIENCE",
            "POSTERN_ALLOW_PROCESS_LOCAL_SESSIONS",
        }
```

In `tests/test_settings_bounds.py`, replace:

```python

#: The three flags, each read through `postern_core/config.py`'s `bool_from_env`.
#:
```

with:

```python

#: The five flags, each read through `postern_core/config.py`'s `bool_from_env`.
#:
```

In `tests/test_settings_bounds.py`, replace:

```python

    WHAT THE TREE ACTUALLY HOLDS, counted rather than assumed: 74 distinct
    ``POSTERN_*`` variables across the swept roots, in two disjoint
    populations. 27 are read directly, and all 27 are strings -- a URL, a
    path, a key id, an issuer, an audience, a key prefix, and the guard's own
    two comma-separated lists of names. 47 are handed to a reader as its ``name``
    argument, and those are the 40 in `BOUNDED`, the 2 in `STORE_BOUNDED`, the
    2 in `VAULT_BOUNDED` and the 3 in `FLAGS`. Nothing is in both and nothing is in neither, which
    `TestEveryEnvironmentReadNamesAnInventoriedVariable::test_the_two_inventories_are_the_whole_tree`
```

with:

```python

    WHAT THE TREE ACTUALLY HOLDS, counted rather than assumed: 83 distinct
    ``POSTERN_*`` variables across the swept roots, in two disjoint
    populations. 32 are read directly, and all 32 are strings -- a URL, a
    path, a key id, an issuer, an audience, a key prefix, and the guard's own
    two comma-separated lists of names. 51 are handed to a reader as its ``name``
    argument, and those are the 42 in `BOUNDED`, the 2 in `STORE_BOUNDED`, the
    2 in `VAULT_BOUNDED` and the 5 in `FLAGS`. Nothing is in both and nothing is in neither, which
    `TestEveryEnvironmentReadNamesAnInventoriedVariable::test_the_two_inventories_are_the_whole_tree`
```

In `tests/test_settings_bounds.py`, replace:

```python
    def test_the_two_inventories_are_the_whole_tree(self) -> None:
        """74 variables, 27 read directly and 47 through a reader, disjoint."""
        direct = {s.name for s in _all_env_sites() if s.shape == "direct" and s.name}
```

with:

```python
    def test_the_two_inventories_are_the_whole_tree(self) -> None:
        """83 variables, 32 read directly and 51 through a reader, disjoint."""
        direct = {s.name for s in _all_env_sites() if s.shape == "direct" and s.name}
```

In `tests/test_settings_bounds.py`, replace:

```python
        assert direct | through == set(KNOWN_ENV)
        assert len(KNOWN_ENV) == 74

```

with:

```python
        assert direct | through == set(KNOWN_ENV)
        assert len(KNOWN_ENV) == 83

```

In `tests/test_settings_bounds.py`, replace:

```python
        """
        assert len(KNOWN_ENV) == 74
        assert len(READ_AS_STRING) == 27
        assert len(FLAGS) == 3
        assert len(BOUNDED_NAMES) == 40
        assert len(STORE_BOUNDED_NAMES) == 2
        assert len(VAULT_BOUNDED_NAMES) == 2
        assert len(BOUNDED_NAMES | STORE_BOUNDED_NAMES | VAULT_BOUNDED_NAMES | FLAGS) == 47
        assert len(names_read_by("api")) == 38
        assert len(names_read_by("confirm")) == 58
        assert len(names_read_by("migrations")) == 3
```

with:

```python
        """
        assert len(KNOWN_ENV) == 83
        assert len(READ_AS_STRING) == 32
        assert len(FLAGS) == 5
        assert len(BOUNDED_NAMES) == 42
        assert len(STORE_BOUNDED_NAMES) == 2
        assert len(VAULT_BOUNDED_NAMES) == 2
        assert len(BOUNDED_NAMES | STORE_BOUNDED_NAMES | VAULT_BOUNDED_NAMES | FLAGS) == 51
        assert len(names_read_by("api")) == 38
        assert len(names_read_by("confirm")) == 67
        assert len(names_read_by("migrations")) == 3
```

- [ ] **Step 2: Run them to verify they fail**

Run: `uv run pytest tests/test_resource_uri.py tests/test_session_token_settings.py tests/test_settings_bounds.py -q`

Expected: FAIL, `2 errors`. The first failure reads `ModuleNotFoundError: No module named 'postern_core.auth.resource_uri'`.

- [ ] **Step 3: Implement**

Create `packages/postern-core/src/postern_core/auth/resource_uri.py` with:

```python
"""RFC 8707 resource indicators: the one normal form both services compare.

A layer-1 session token names the MCP server it is for in ``aud``, and RFC
8707 section 2 says what that value must be: "an absolute URI" that "MUST NOT
include a fragment component". Two places compare such a value with a
configured one: ``POST /token`` in `services/confirm`, against a ``resource``
parameter a client sends, and `services/api`'s startup refusal, against its
own ``POSTERN_AUDIENCE``. Both import this module so the two cannot disagree
about what "the same resource" means; ``.importlinter`` forbids either
service from importing the other.

THE NORMALIZATION IS RFC 3986 SECTIONS 6.2.2.1 AND 6.2.3 AND NOTHING ELSE.
The scheme and the host are lower-cased, an empty port or the scheme's default
port is removed, and an empty path becomes ``/``. The path stays
case-sensitive, percent-encoding is compared exactly as sent, and a trailing
slash on a non-empty path is significant, so ``https://mcp.example/mcp`` and
``https://mcp.example/mcp/`` are two resources. A configured audience is
required to be in this form already, so the string an operator types into both
services is the string compared.
"""

from __future__ import annotations

from urllib.parse import urlsplit

#: The ports RFC 3986 section 6.2.3 lets a normalizer drop, by scheme.
_DEFAULT_PORTS = {"https": 443, "http": 80}


def normalize_resource(value: str) -> str | None:
    """``value`` in the normal form above, or ``None`` when it cannot name a resource.

    ``None`` for an empty value, a value carrying ``#`` anywhere (a fragment,
    empty or not), a relative reference, a value with no host, and a port
    that does not parse. The caller answers each ``invalid_target``.
    """
    if not value or "#" in value:
        return None
    try:
        parts = urlsplit(value)
        port = parts.port
    except ValueError:
        return None
    hostname = parts.hostname
    if not parts.scheme or not hostname:
        return None
    scheme = parts.scheme.lower()
    host = f"[{hostname}]" if ":" in hostname else hostname
    authority = host if port is None or port == _DEFAULT_PORTS.get(scheme) else f"{host}:{port}"
    userinfo, at, _ = parts.netloc.rpartition("@")
    if at:
        authority = f"{userinfo}@{authority}"
    query = f"?{parts.query}" if "?" in value else ""
    return f"{scheme}://{authority}{parts.path or '/'}{query}"


def is_normal_https_resource(value: str) -> bool:
    """Whether ``value`` is an absolute ``https`` URI with a host, already in normal form."""
    return value.startswith("https://") and normalize_resource(value) == value
```

In `packages/postern-core/src/postern_core/env_inventory.py`, replace:

```python
#: Generated from the syntax tree on 2026-09-27 rather than typed, and pinned
#: against it by `tests/test_settings_bounds.py` on every run. 74 rows since
#: 2026-09-30: 27 strings (25 settings plus this guard's own two lists), 44
#: numbers, 3 flags. The eight ``POSTERN_VAULT_*`` rows below the device-code
#: block arrived on 2026-09-29; ``POSTERN_DEVICE_APP_LINK_URI`` and the seven
```

with:

```python
#: Generated from the syntax tree on 2026-09-27 rather than typed, and pinned
#: against it by `tests/test_settings_bounds.py` on every run. 83 rows since
#: 2026-09-30: 32 strings (30 settings plus this guard's own two lists), 46
#: numbers, 5 flags. The eight ``POSTERN_VAULT_*`` rows below the device-code
#: block arrived on 2026-09-29; ``POSTERN_DEVICE_APP_LINK_URI`` and the seven
```

In `packages/postern-core/src/postern_core/env_inventory.py`, replace:

```python
#: ``POSTERN_CONFIRM_ASSERTION_MAX_LIFETIME_SECONDS`` arrived later that day,
#: and ``POSTERN_CONFIRM_PAIRING_ENRICHER_TIMEOUT_SECONDS`` after it.
INVENTORY: tuple[EnvVar, ...] = (
```

with:

```python
#: ``POSTERN_CONFIRM_ASSERTION_MAX_LIFETIME_SECONDS`` arrived later that day,
#: and ``POSTERN_CONFIRM_PAIRING_ENRICHER_TIMEOUT_SECONDS`` after it. The nine
#: session-token rows arrived with the layer-1 session token.
INVENTORY: tuple[EnvVar, ...] = (
```

In `packages/postern-core/src/postern_core/env_inventory.py`, replace:

```python
    EnvVar(REQUIRED_ENV, "string", EVERYWHERE),
    EnvVar("POSTERN_APP_ASSERTION_AUDIENCE", "string", ("confirm",)),
```

with:

```python
    EnvVar(REQUIRED_ENV, "string", EVERYWHERE),
    EnvVar("POSTERN_ALLOW_NON_URI_AUDIENCE", "flag", ("confirm",)),
    EnvVar("POSTERN_ALLOW_PROCESS_LOCAL_SESSIONS", "flag", ("confirm",)),
    EnvVar("POSTERN_APP_ASSERTION_AUDIENCE", "string", ("confirm",)),
```

In `packages/postern-core/src/postern_core/env_inventory.py`, replace:

```python
    EnvVar("POSTERN_CONFIRM_RATE_LIMIT_SCAN", "number", ("confirm",)),
    EnvVar("POSTERN_CONFIRM_RATE_LIMIT_TOKEN", "number", ("confirm",)),
```

with:

```python
    EnvVar("POSTERN_CONFIRM_RATE_LIMIT_SCAN", "number", ("confirm",)),
    EnvVar("POSTERN_CONFIRM_RATE_LIMIT_SESSION_JWKS", "number", ("confirm",)),
    EnvVar("POSTERN_CONFIRM_RATE_LIMIT_TOKEN", "number", ("confirm",)),
```

In `packages/postern-core/src/postern_core/env_inventory.py`, replace:

```python
    EnvVar("POSTERN_MAX_DEVICE_CODES", "number", ("confirm",)),
    EnvVar("POSTERN_MAX_SCOPES_LENGTH", "number", ("confirm",)),
```

with:

```python
    EnvVar("POSTERN_MAX_DEVICE_CODES", "number", ("confirm",)),
    EnvVar("POSTERN_MAX_REFRESH_SESSIONS", "number", ("confirm",)),
    EnvVar("POSTERN_MAX_SCOPES_LENGTH", "number", ("confirm",)),
```

In `packages/postern-core/src/postern_core/env_inventory.py`, replace:

```python
    EnvVar("POSTERN_REQUIRE_REDIS", "flag", BOTH),
    EnvVar("POSTERN_STRICT_HEADERS", "flag", ("api",)),
```

with:

```python
    EnvVar("POSTERN_REQUIRE_REDIS", "flag", BOTH),
    EnvVar("POSTERN_SESSION_KEY_KID", "string", ("confirm",)),
    EnvVar("POSTERN_SESSION_KEY_PEM_PATH", "string", ("confirm",)),
    EnvVar("POSTERN_SESSION_TOKEN_AUDIENCE", "string", ("confirm",)),
    EnvVar("POSTERN_SESSION_TOKEN_ISSUER", "string", ("confirm",)),
    EnvVar("POSTERN_STRICT_HEADERS", "flag", ("api",)),
```

In `packages/postern-core/src/postern_core/env_inventory.py`, replace:

```python
    EnvVar("POSTERN_VAULT_READ_KEY_NAME", "string", BOTH),
    EnvVar("POSTERN_VAULT_TIMEOUT_SECONDS", "number", BOTH),
```

with:

```python
    EnvVar("POSTERN_VAULT_READ_KEY_NAME", "string", BOTH),
    EnvVar("POSTERN_VAULT_SESSION_KEY_NAME", "string", ("confirm",)),
    EnvVar("POSTERN_VAULT_TIMEOUT_SECONDS", "number", BOTH),
```

In `services/confirm/settings.py`, replace:

```python

import os
```

with:

```python

import logging
import os
```

In `services/confirm/settings.py`, replace:

```python
)
from postern_core.auth.vault import VaultSettings, vault_from_env
from postern_core.config import float_from_env, int_from_env

```

with:

```python
)
from postern_core.auth.resource_uri import is_normal_https_resource
from postern_core.auth.vault import VaultSettings, vault_from_env
from postern_core.config import bool_from_env, float_from_env, int_from_env

```

In `services/confirm/settings.py`, replace:

```python
    MAX_ASSERTION_MAX_LIFETIME_SECONDS,
)

#: The scope string ``POST /device_authorization`` substitutes when the caller
```

with:

```python
    MAX_ASSERTION_MAX_LIFETIME_SECONDS,
)

logger = logging.getLogger(__name__)

#: The scope string ``POST /device_authorization`` substitutes when the caller
```

In `services/confirm/settings.py`, replace:

```python
    customer_rate_limit_scan: int = 10

```

with:

```python
    customer_rate_limit_scan: int = 10
    # THE LAYER-1 SESSION TOKEN (dev-docs/device-grant-session-token-spec.md
    # section 2). A THIRD signing key, which signs the access token
    # ``POST /token`` issues and nothing else, published at
    # ``/session/jwks.json``. The kid, PEM path and transit key name follow
    # the write key's three fields above and reach the same
    # `choose_key_source`, so the Vault, PEM and generated branches and the
    # refusal of both at once are inherited rather than restated.
    session_key_pem_path: str | None = None
    session_key_kid: str = "session-1"
    vault_session_key_name: str = "postern-session"
    # The ``iss`` of every access token: this service's public issuer URL.
    # `check_session_token_settings` refuses one that is not ``https`` with a
    # host, or that equals another issuer this process knows.
    session_token_issuer: str = "https://auth.postern.internal"  # noqa: S105
    # The ``aud`` of every access token: the MCP server's resource URI, which
    # must equal ``services/api``'s ``POSTERN_AUDIENCE``. The DEFAULT IS A
    # LOCAL-ONLY VALUE that `check_session_token_settings` refuses unless
    # ``allow_non_uri_audience`` is set, because RFC 8707 section 2 requires
    # an absolute URI.
    session_token_audience: str = "postern"  # noqa: S105
    # Two development flags, both off by default, because a default is what a
    # hand-built settings object gets and these defaults are the ones a
    # deployment may run. `ConfirmSettings.for_testing` sets both.
    allow_non_uri_audience: bool = False
    allow_process_local_sessions: bool = False
    # The ceiling on live refresh-token families: ``max_device_codes`` times
    # the lifetime ratio (3,600 s against 900 s), so a store in which every
    # live device code were exchanged as fast as codes can exist still fits.
    max_refresh_sessions: int = 40_000
    # Per-address requests a minute to ``/session/jwks.json``, fetched by
    # every ``services/api`` worker process on a cache miss.
    rate_limit_session_jwks: int = 300

```

In `services/confirm/settings.py`, replace:

```python
            customer_rate_limit_scan=_positive_int("POSTERN_CONFIRM_CUSTOMER_RATE_LIMIT_SCAN", 10),
        )
```

with:

```python
            customer_rate_limit_scan=_positive_int("POSTERN_CONFIRM_CUSTOMER_RATE_LIMIT_SCAN", 10),
            session_key_pem_path=os.environ.get("POSTERN_SESSION_KEY_PEM_PATH") or None,
            session_key_kid=os.environ.get("POSTERN_SESSION_KEY_KID", "session-1"),
            vault_session_key_name=os.environ.get(
                "POSTERN_VAULT_SESSION_KEY_NAME", "postern-session"
            ),
            session_token_issuer=os.environ.get(
                "POSTERN_SESSION_TOKEN_ISSUER", "https://auth.postern.internal"
            ),
            session_token_audience=os.environ.get("POSTERN_SESSION_TOKEN_AUDIENCE", "postern"),
            allow_non_uri_audience=bool_from_env(
                "POSTERN_ALLOW_NON_URI_AUDIENCE",
                False,
                because=(
                    "It lets a local stack run with an access-token audience that is not "
                    "an absolute https URI, which RFC 8707 section 2 requires."
                ),
            ),
            allow_process_local_sessions=bool_from_env(
                "POSTERN_ALLOW_PROCESS_LOCAL_SESSIONS",
                False,
                because=(
                    "It lets the device grant run without POSTERN_REDIS_URL, so refresh "
                    "families and recalls live in this process and nowhere else."
                ),
            ),
            max_refresh_sessions=int_from_env(
                "POSTERN_MAX_REFRESH_SESSIONS",
                40_000,
                minimum=1,
                because=(
                    "It is how many refresh-token families the store will hold; at zero "
                    "the cap is met by an empty store and every exchange is refused."
                ),
            ),
            rate_limit_session_jwks=_positive_int("POSTERN_CONFIRM_RATE_LIMIT_SESSION_JWKS", 300),
        )
```

In `services/confirm/settings.py`, replace:

```python
            database_url=os.environ.get("POSTERN_DATABASE_URL") or cls.database_url,
        )
```

with:

```python
            database_url=os.environ.get("POSTERN_DATABASE_URL") or cls.database_url,
            # Both development flags, and only here: the audience default,
            # ``postern``, is not a URI, and a test process has no shared Redis.
            allow_non_uri_audience=True,
            allow_process_local_sessions=True,
        )


def check_session_token_settings(settings: ConfirmSettings) -> None:
    """Refuse a session-token configuration no deployment may run, or return.

    ``ValueError`` naming the offending values, for each of:

    - ``session_token_issuer`` that is not ``https`` with a hostname, or that
      carries a query or a fragment;
    - ``session_token_issuer`` equal to ``write_token_issuer`` or to
      ``app_assertion_issuer``: one issuer string per token type;
    - ``session_token_audience`` that is not an absolute ``https`` URI with a
      host, already in `postern_core.auth.resource_uri`'s normal form, unless
      ``allow_non_uri_audience`` is set, in which case a warning naming the
      flag is logged instead;
    - ``session_token_audience`` equal to ``app_assertion_audience``, the
      rule this module's docstring argues from the other side.

    CALLED BY ``create_confirm_app``, NOT BY ``__post_init__``, so a settings
    object built by hand is refused where a deployment would be, at startup,
    and a test that builds one without building an app is unaffected.
    Equality with the api's ``POSTERN_AUDIENCE`` cannot be checked here: that
    is another deployment, and a mismatch fails closed at the api.
    """
    issuer = settings.session_token_issuer
    parts = urlsplit(issuer)
    if parts.scheme != "https" or not parts.hostname or "?" in issuer or "#" in issuer:
        raise ValueError(
            f"POSTERN_SESSION_TOKEN_ISSUER ({issuer!r}) must be an https URL with a hostname "
            "and no query or fragment. It is the iss of every access token POST /token issues."
        )
    for name, other in (
        ("POSTERN_WRITE_TOKEN_ISSUER", settings.write_token_issuer),
        ("POSTERN_APP_ASSERTION_ISSUER", settings.app_assertion_issuer),
    ):
        if issuer == other:
            raise ValueError(
                f"POSTERN_SESSION_TOKEN_ISSUER ({issuer!r}) must differ from {name} ({other!r}). "
                "Each token type carries its own issuer, so no verifier can mistake one for "
                "another."
            )
    audience = settings.session_token_audience
    if not is_normal_https_resource(audience):
        if not settings.allow_non_uri_audience:
            raise ValueError(
                f"POSTERN_SESSION_TOKEN_AUDIENCE ({audience!r}) must be the MCP server's "
                "resource URI: an absolute https URI with a host and no fragment (RFC 8707 "
                "section 2), with a lower-case scheme and host, no default port and a "
                "non-empty path. Set it to the same value as services/api's POSTERN_AUDIENCE, "
                "or set POSTERN_ALLOW_NON_URI_AUDIENCE for a local stack."
            )
        logger.warning(
            "POSTERN_ALLOW_NON_URI_AUDIENCE is set: access tokens carry the audience %r, "
            "which is not an absolute https URI. No deployment may run this way.",
            audience,
        )
    if audience == settings.app_assertion_audience:
        raise ValueError(
            f"POSTERN_SESSION_TOKEN_AUDIENCE ({audience!r}) must differ from "
            "POSTERN_APP_ASSERTION_AUDIENCE: a token good enough to reach the MCP server "
            "must not be good enough to approve a payment."
        )
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `uv run pytest tests/test_resource_uri.py tests/test_session_token_settings.py tests/test_settings_bounds.py -q`

Expected: 433 passed

- [ ] **Step 5: Format, then run the gate**

Run: `uv run ruff format packages services tests && make ci`

Expected: exit 0 (3552 passed at validation).

- [ ] **Step 6: Commit**

```bash
git add packages/postern-core/src/postern_core/auth/resource_uri.py packages/postern-core/src/postern_core/env_inventory.py services/confirm/settings.py tests/test_resource_uri.py tests/test_session_token_settings.py tests/test_settings_bounds.py
git commit -m "feat(confirm): settings and startup checks for the layer-1 session token" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 2: The SESSION key, its minter and `/session/jwks.json`

Spec sections 2 (the key, the JWKS path, kid and rotation) and 3 (the access token), and section 10's public path and rate-limit row. The key is built by the same `choose_key_source` call the other two keys use, so the Vault, PEM and generated branches and the refusal of both are inherited. Nothing signs with it until Task 6.

**Files:**
- Modify: `services/confirm/auth.py` (`PUBLIC_PATHS`)
- Modify: `services/confirm/jwks.py` (`SESSION_JWKS_PATH`, `session_jwks_route`)
- Modify: `services/confirm/main.py` (`create_confirm_app`)
- Modify: `services/confirm/rate_limit.py` (`DEFAULT_LIMITS`, `limits_from_settings`)
- Create: `services/confirm/session_token.py` (`ACCESS_TOKEN_LIFETIME_SECONDS`, `SessionClaims`, `SessionTokenMinter`, `build_session_minter`)
- Modify: `tests/test_confirm_auth.py`
- Modify: `tests/test_confirm_body_limit.py`
- Modify: `tests/test_confirm_rate_limit.py`
- Modify: `tests/test_ephemeral_key_warning.py`
- Create: `tests/test_session_token.py`

- [ ] **Step 1: Write the failing tests**

In `tests/test_confirm_auth.py`, replace:

```python

def test_the_public_path_list_is_exactly_these_eight() -> None:
    """Adding a ninth must be a deliberate, reviewed act.

```

with:

```python

def test_the_public_path_list_is_exactly_these_nine() -> None:
    """Adding a tenth must be a deliberate, reviewed act.

```

In `tests/test_confirm_auth.py`, replace:

```python
    ``dev-docs/decisions/0021-public-html-on-the-write-key-service.md`` is
    where serving them here was decided.
    """
```

with:

```python
    ``dev-docs/decisions/0021-public-html-on-the-write-key-service.md`` is
    where serving them here was decided. ``/session/jwks.json`` is the
    session key's public half, which ``services/api``'s verifier fetches.
    """
```

In `tests/test_confirm_auth.py`, replace:

```python
        "/.well-known/jwks.json",
        "/device_authorization",
```

with:

```python
        "/.well-known/jwks.json",
        "/session/jwks.json",
        "/device_authorization",
```

In `tests/test_confirm_body_limit.py`, replace:

```python
        ("/.well-known/jwks.json", "application/json"),
        ("/verify", "text/plain"),
```

with:

```python
        ("/.well-known/jwks.json", "application/json"),
        ("/session/jwks.json", "application/json"),
        ("/verify", "text/plain"),
```

In `tests/test_confirm_rate_limit.py`, replace:

```python
            "/verify.css",
        ):
```

with:

```python
            "/verify.css",
            "/session/jwks.json",
        ):
```

In `tests/test_confirm_rate_limit.py`, replace:

```python
        ("POSTERN_CONFIRM_RATE_LIMIT_VERIFY_CSS", "rate_limit_verify_css"),
    ]
```

with:

```python
        ("POSTERN_CONFIRM_RATE_LIMIT_VERIFY_CSS", "rate_limit_verify_css"),
        ("POSTERN_CONFIRM_RATE_LIMIT_SESSION_JWKS", "rate_limit_session_jwks"),
    ]
```

In `tests/test_confirm_rate_limit.py`, replace:

```python
                verify_css=settings.rate_limit_verify_css,
            )
```

with:

```python
                verify_css=settings.rate_limit_verify_css,
                session_jwks=settings.rate_limit_session_jwks,
            )
```

In `tests/test_ephemeral_key_warning.py`, replace:

```python
        read_key_pem_path=_private_pem(tmp_path, "read.pem", "read-1"),
        # Required since the confirm service gained inbound authentication:
```

with:

```python
        read_key_pem_path=_private_pem(tmp_path, "read.pem", "read-1"),
        session_key_pem_path=_private_pem(tmp_path, "session.pem", "session-1"),
        # Required since the confirm service gained inbound authentication:
```

In `tests/test_ephemeral_key_warning.py`, replace:

```python
            ),
            2,  # write + read (device grant exception)
            id="confirm",
```

with:

```python
            ),
            3,  # write + read (device grant exception) + session
            id="confirm",
```

In `tests/test_ephemeral_key_warning.py`, replace:

```python
        assert "POSTERN_READ_KEY_PEM_PATH" in messages[0]
    # The confirm service has warnings for both write and read keys.
    if expected_count == 2:
        write_msg = [m for m in messages if "POSTERN_WRITE_KEY_PEM_PATH" in m]
        read_msg = [m for m in messages if "POSTERN_READ_KEY_PEM_PATH" in m]
        assert len(write_msg) == 1
        assert len(read_msg) == 1

```

with:

```python
        assert "POSTERN_READ_KEY_PEM_PATH" in messages[0]
    # The confirm service has warnings for the write, read and session keys.
    if expected_count == 3:
        write_msg = [m for m in messages if "POSTERN_WRITE_KEY_PEM_PATH" in m]
        read_msg = [m for m in messages if "POSTERN_READ_KEY_PEM_PATH" in m]
        session_msg = [m for m in messages if "POSTERN_SESSION_KEY_PEM_PATH" in m]
        assert len(write_msg) == 1
        assert len(read_msg) == 1
        assert len(session_msg) == 1

```

Create `tests/test_session_token.py` with:

```python
"""The layer-1 access token, the SESSION key and ``/session/jwks.json``.

Spec sections 2 and 3 of ``dev-docs/device-grant-session-token-spec.md``: a
third key built by the same ``choose_key_source`` call as the other two, a
minter whose claim set is exactly the table, and a JWKS route of its own that
never shares a kid or a modulus with the write set.
"""

from __future__ import annotations

import uuid
import warnings
from dataclasses import replace
from pathlib import Path
from typing import Any

import httpx2
import pytest
from joserfc import jwt
from joserfc.jwk import KeySet, RSAKey
from postern_core.auth.device_keys import no_enrolled_devices
from postern_core.auth.keys import FileKeySource, GeneratedKeySource
from postern_core.auth.vault import VaultSettings, VaultTransitKeySource
from postern_core.identity import CustomerRef
from starlette.applications import Starlette

from services.confirm.jwks import JWKS_PATH, SESSION_JWKS_PATH
from services.confirm.main import create_confirm_app
from services.confirm.rate_limit import DEFAULT_LIMITS, RATE_LIMIT_WINDOW_SECONDS, Limit
from services.confirm.session_token import (
    ACCESS_TOKEN_LIFETIME_SECONDS,
    SessionTokenMinter,
    build_session_minter,
)
from services.confirm.settings import ConfirmSettings

CUSTOMER = CustomerRef(value="cust_7f3a")
VAULT = VaultSettings(
    address="http://vault.invalid:8200",
    token="hvs.notarealtoken",  # noqa: S106 -- a literal in a test, not a credential
    token_path=None,
    mount="transit",
    timeout_seconds=1.0,
    public_key_ttl_seconds=300.0,
)


def _minter() -> tuple[SessionTokenMinter, GeneratedKeySource]:
    source = GeneratedKeySource(kid="session-1")
    minter = SessionTokenMinter(
        issuer="https://auth.postern.internal",
        audience="https://mcp.postern.internal/mcp",
        key_source=source,
    )
    return minter, source


class TestTheAccessToken:
    def test_the_claim_set_is_exactly_the_table(self) -> None:
        minter, source = _minter()
        claims = minter.prepare(
            customer=CUSTOMER, client_id="claude-code", scope="accounts:read", sid="s" * 22
        )
        token = minter.sign(claims)
        decoded = jwt.decode(token, KeySet.import_key_set(source.public_jwks()))
        assert set(decoded.claims) == {
            "iss",
            "aud",
            "sub",
            "client_id",
            "client_id_verified",
            "scope",
            "sid",
            "jti",
            "iat",
            "exp",
        }
        assert decoded.claims["iss"] == "https://auth.postern.internal"
        assert decoded.claims["aud"] == "https://mcp.postern.internal/mcp"
        assert decoded.claims["sub"] == "cust_7f3a"
        assert decoded.claims["client_id"] == "claude-code"
        assert decoded.claims["client_id_verified"] is False
        assert decoded.claims["scope"] == "accounts:read"
        assert decoded.claims["sid"] == "s" * 22
        assert decoded.claims["exp"] - decoded.claims["iat"] == ACCESS_TOKEN_LIFETIME_SECONDS
        assert ACCESS_TOKEN_LIFETIME_SECONDS == 600
        assert "act" not in decoded.claims
        assert "nbf" not in decoded.claims

    def test_the_header_names_the_session_kid_and_rs256(self) -> None:
        minter, source = _minter()
        token = minter.sign(
            minter.prepare(customer=CUSTOMER, client_id="c", scope="accounts:read", sid="x")
        )
        decoded = jwt.decode(token, KeySet.import_key_set(source.public_jwks()))
        assert decoded.header["alg"] == "RS256"
        assert decoded.header["kid"] == "session-1"

    def test_each_prepare_draws_a_fresh_uuid4_jti(self) -> None:
        minter, _ = _minter()
        drawn = {
            minter.prepare(customer=CUSTOMER, client_id="c", scope="s", sid="x").jti
            for _ in range(50)
        }
        assert len(drawn) == 50
        assert all(uuid.UUID(jti).version == 4 for jti in drawn)

    def test_prepare_reads_the_clock_once_and_the_claims_are_frozen(self) -> None:
        minter, _ = _minter()
        claims = minter.prepare(customer=CUSTOMER, client_id="c", scope="s", sid="x")
        assert claims.as_claims()["exp"] == claims.iat + 600
        with pytest.raises(AttributeError):
            claims.jti = "chosen"  # type: ignore[misc]


class TestTheSessionKeySource:
    def test_neither_branch_generates_and_warns_naming_the_session_variable(self) -> None:
        with pytest.warns(RuntimeWarning, match="POSTERN_SESSION_KEY_PEM_PATH") as caught:
            _, source = build_session_minter(ConfirmSettings.for_testing())
        assert isinstance(source, GeneratedKeySource)
        assert "SESSION signing key generated in process" in str(caught[0].message)

    def test_a_pem_gives_a_file_source_under_the_session_kid(self, tmp_path: Path) -> None:
        pem = tmp_path / "session.pem"
        pem.write_bytes(RSAKey.generate_key(2048).as_pem(private=True))
        settings = replace(
            ConfirmSettings.for_testing(), session_key_pem_path=str(pem), session_key_kid="s-9"
        )
        _, source = build_session_minter(settings)
        assert isinstance(source, FileKeySource)
        assert [key["kid"] for key in source.public_jwks()["keys"]] == ["s-9"]

    def test_a_public_key_pem_is_refused_at_startup(self, tmp_path: Path) -> None:
        pem = tmp_path / "public.pem"
        pem.write_bytes(RSAKey.generate_key(2048).as_pem(private=False))
        settings = replace(ConfirmSettings.for_testing(), session_key_pem_path=str(pem))
        with pytest.raises(ValueError, match="public key"):
            build_session_minter(settings)

    def test_a_vault_gives_a_transit_source_over_the_session_key(self) -> None:
        settings = replace(ConfirmSettings.for_testing(), vault=VAULT)
        _, source = build_session_minter(settings)
        assert isinstance(source, VaultTransitKeySource)
        source.close()

    def test_a_vault_and_a_pem_together_are_refused(self, tmp_path: Path) -> None:
        pem = tmp_path / "session.pem"
        pem.write_bytes(RSAKey.generate_key(2048).as_pem(private=True))
        settings = replace(
            ConfirmSettings.for_testing(), vault=VAULT, session_key_pem_path=str(pem)
        )
        with pytest.raises(ValueError, match="POSTERN_SESSION_KEY_PEM_PATH"):
            build_session_minter(settings)


def _app() -> Starlette:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", RuntimeWarning)
        return create_confirm_app(
            ConfirmSettings.for_testing(), device_key_store=no_enrolled_devices()
        )


async def _get(app: Starlette, path: str) -> httpx2.Response:
    async with httpx2.AsyncClient(
        transport=httpx2.ASGITransport(app=app), base_url="https://auth.test"
    ) as client:
        return await client.get(path)


class TestTheSessionJwksRoute:
    async def test_it_serves_the_session_key_and_nothing_else(self) -> None:
        app = _app()
        response = await _get(app, SESSION_JWKS_PATH)
        assert response.status_code == 200
        assert response.json() == app.state.postern_session_key_source.public_jwks()
        assert [key["kid"] for key in response.json()["keys"]] == ["session-1"]

    async def test_the_well_known_set_stays_write_only(self) -> None:
        app = _app()
        response = await _get(app, JWKS_PATH)
        assert response.json() == app.state.postern_write_key_source.public_jwks()

    async def test_the_two_sets_share_no_kid_and_no_modulus(self) -> None:
        app = _app()
        write: dict[str, Any] = (await _get(app, JWKS_PATH)).json()
        session: dict[str, Any] = (await _get(app, SESSION_JWKS_PATH)).json()
        assert {k["kid"] for k in write["keys"]} & {k["kid"] for k in session["keys"]} == set()
        assert {k["n"] for k in write["keys"]} & {k["n"] for k in session["keys"]} == set()

    async def test_a_token_the_app_mints_verifies_against_the_session_set_only(self) -> None:
        app = _app()
        minter: SessionTokenMinter = app.state.session_minter
        token = minter.sign(
            minter.prepare(customer=CUSTOMER, client_id="c", scope="accounts:read", sid="x")
        )
        session = (await _get(app, SESSION_JWKS_PATH)).json()
        write = (await _get(app, JWKS_PATH)).json()
        jwt.decode(token, KeySet.import_key_set(session))
        with pytest.raises(Exception):  # noqa: B017 -- any refusal to verify
            jwt.decode(token, KeySet.import_key_set(write))

    async def test_it_needs_no_assertion(self) -> None:
        response = await _get(_app(), SESSION_JWKS_PATH)
        assert response.status_code == 200

    def test_it_carries_its_own_rate_limit(self) -> None:
        assert DEFAULT_LIMITS[SESSION_JWKS_PATH] == Limit(300, RATE_LIMIT_WINDOW_SECONDS)
```

- [ ] **Step 2: Run them to verify they fail**

Run: `uv run pytest tests/test_confirm_auth.py tests/test_confirm_body_limit.py tests/test_confirm_rate_limit.py tests/test_ephemeral_key_warning.py tests/test_session_token.py -q`

Expected: FAIL, `1 error`. The first failure reads `ImportError: cannot import name 'SESSION_JWKS_PATH' from 'services.confirm.jwks'`.

- [ ] **Step 3: Implement**

In `services/confirm/auth.py`, replace:

```python
#:     The page's only stylesheet, so ``style-src 'self'`` has a target.
PUBLIC_PATHS = frozenset(
```

with:

```python
#:     The page's only stylesheet, so ``style-src 'self'`` has a target.
#:
#: ``/session/jwks.json``
#:     The PUBLIC half of the session key, which signs the layer-1 access
#:     tokens ``POST /token`` issues. ``services/api``'s verifier fetches it
#:     holding no assertion, which is why it is here; like the write set above
#:     it carries no private material (``services/confirm/jwks.py``).
PUBLIC_PATHS = frozenset(
```

In `services/confirm/auth.py`, replace:

```python
        "/.well-known/jwks.json",
        "/device_authorization",
```

with:

```python
        "/.well-known/jwks.json",
        "/session/jwks.json",
        "/device_authorization",
```

In `services/confirm/jwks.py`, replace:

```python
`services/api/jwks.py` carries the matching comment.
"""
```

with:

```python
`services/api/jwks.py` carries the matching comment.

A SECOND ROUTE, `session_jwks_route`, publishes the SESSION key at
`SESSION_JWKS_PATH` (``dev-docs/device-grant-session-token-spec.md`` section
2). It is a separate route with its own path and NOT a path parameter on
`jwks_route`, for the reason above turned around: `jwks_route`'s body is the
one that must change in step with the api's copy, and a merged or
parameterised publisher is the convenience that measurement priced. The two
sets share no kid and no modulus, and ``/.well-known/jwks.json`` stays
write-only.
"""
```

In `services/confirm/jwks.py`, replace:

```python
JWKS_PATH = "/.well-known/jwks.json"


def jwks_route(source: KeySource) -> Route:
```

with:

```python
JWKS_PATH = "/.well-known/jwks.json"

#: Where the SESSION key's public half is published, for ``services/api``'s
#: verifier to fetch. Public (`services/confirm/auth.py`'s ``PUBLIC_PATHS``).
SESSION_JWKS_PATH = "/session/jwks.json"


def jwks_route(source: KeySource) -> Route:
```

In `services/confirm/jwks.py`, replace:

```python
    return Route(JWKS_PATH, handler, methods=["GET"])
```

with:

```python
    return Route(JWKS_PATH, handler, methods=["GET"])


def session_jwks_route(source: KeySource) -> Route:
    """The session key set, and only it, at `SESSION_JWKS_PATH`."""

    async def handler(_: Request) -> JSONResponse:
        return JSONResponse(source.public_jwks())

    return Route(SESSION_JWKS_PATH, handler, methods=["GET"])
```

In `services/confirm/main.py`, replace:

```python
from services.confirm.device_auth import PAIRING_ENRICHMENT_SLOTS, device_auth_routes
from services.confirm.jwks import jwks_route
from services.confirm.minter import build_write_minter
```

with:

```python
from services.confirm.device_auth import PAIRING_ENRICHMENT_SLOTS, device_auth_routes
from services.confirm.jwks import jwks_route, session_jwks_route
from services.confirm.minter import build_write_minter
```

In `services/confirm/main.py`, replace:

```python
)
from services.confirm.settings import ConfirmSettings
```

with:

```python
)
from services.confirm.session_token import build_session_minter
from services.confirm.settings import ConfirmSettings
```

In `services/confirm/main.py`, replace:

```python

    # --- Read key / minter (device grant exception) ---
```

with:

```python

    # --- Session key / minter (the layer-1 access token) ---
    #
    # A THIRD KEY, which signs the access tokens `POST /token` issues and
    # nothing else, published at `/session/jwks.json` beside the write set and
    # never inside it. `services/confirm/session_token.py` says why it is not
    # the read key and not `InternalTokenMinter`.
    session_minter, session_key_source = build_session_minter(settings)

    # --- Read key / minter (device grant exception) ---
```

In `services/confirm/main.py`, replace:

```python
    routes: list[Route] = (
        [jwks_route(write_key_source)]
        + device_auth_routes(
```

with:

```python
    routes: list[Route] = (
        [jwks_route(write_key_source), session_jwks_route(session_key_source)]
        + device_auth_routes(
```

In `services/confirm/main.py`, replace:

```python
                    verify_css=settings.rate_limit_verify_css,
                ),
```

with:

```python
                    verify_css=settings.rate_limit_verify_css,
                    session_jwks=settings.rate_limit_session_jwks,
                ),
```

In `services/confirm/main.py`, replace:

```python
    app.state.postern_write_key_source = write_key_source
    app.state.postern_read_key_source = read_key_source
```

with:

```python
    app.state.postern_write_key_source = write_key_source
    app.state.postern_session_key_source = session_key_source
    app.state.postern_read_key_source = read_key_source
```

In `services/confirm/main.py`, replace:

```python
    app.state.write_minter = _write_minter
    app.state.device_code_store = device_code_store
```

with:

```python
    app.state.write_minter = _write_minter
    app.state.session_minter = session_minter
    app.state.device_code_store = device_code_store
```

In `services/confirm/rate_limit.py`, replace:

```python
    "/verify.css": Limit(requests=60, window_seconds=60),
}
```

with:

```python
    "/verify.css": Limit(requests=60, window_seconds=60),
    # Fetched by every ``services/api`` worker process on a cache miss, which
    # its verifier floors at one per 30 seconds per unknown kid plus one per
    # TTL; replicas may share one NAT address, so the ceiling is generous.
    "/session/jwks.json": Limit(requests=300, window_seconds=60),
}
```

In `services/confirm/rate_limit.py`, replace:

```python
    verify_css: int,
) -> dict[str, Limit]:
    """Build the per-path limit map from ten per-minute request counts.

```

with:

```python
    verify_css: int,
    session_jwks: int,
) -> dict[str, Limit]:
    """Build the per-path limit map from eleven per-minute request counts.

```

In `services/confirm/rate_limit.py`, replace:

```python
        "/verify.css": Limit(verify_css, RATE_LIMIT_WINDOW_SECONDS),
    }
```

with:

```python
        "/verify.css": Limit(verify_css, RATE_LIMIT_WINDOW_SECONDS),
        "/session/jwks.json": Limit(session_jwks, RATE_LIMIT_WINDOW_SECONDS),
    }
```

Create `services/confirm/session_token.py` with:

```python
"""The layer-1 access token ``POST /token`` issues, and the key that signs it.

TWO LAYERS, AND THIS IS THE FIRST ONE. Handoff section 7.1 separates the AI
client talking to the MCP server (layer 1) from the MCP server talking to the
backend with a 60-second delegation token (layer 2). This module mints only
the first kind: its ``aud`` is the MCP server ``services/api`` serves, its key
signs nothing else, and it carries no ``act`` claim, so no domain service and
no Istio gateway configured for layer 2 accepts it.

NOT ``InternalTokenMinter``. That class's delegation shape -- ``act``, a fixed
60-second life, a domain-service audience -- is exactly the conflation
``dev-docs/device-grant-session-token-spec.md`` removes, so reusing it would
put the shape back one keyword argument away.

TWO STEPS, ``prepare`` then ``sign``, because ``POST /token`` records the
``jti`` in the refresh-session store BEFORE the token exists: a recall at
``POST /scan`` that finds the family must be able to name every token it can
ever have issued. ``prepare`` draws the ``jti`` and reads the clock once;
``sign`` only signs.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass
from typing import Any

from postern_core.auth.keys import KeySource, choose_key_source
from postern_core.identity import CustomerRef

from services.confirm.settings import ConfirmSettings

#: How long an access token lives, in seconds. A code constant rather than a
#: setting: the family's absolute lifetime is one hour and this is a tenth of
#: it, and decision record 0010's amendment counts on the number.
ACCESS_TOKEN_LIFETIME_SECONDS = 600


@dataclass(frozen=True, slots=True)
class SessionClaims:
    """Every claim one access token carries, frozen before it is signed."""

    iss: str
    aud: str
    sub: str
    client_id: str
    scope: str
    sid: str
    jti: str
    iat: int

    @property
    def exp(self) -> int:
        """``iat`` plus `ACCESS_TOKEN_LIFETIME_SECONDS`."""
        return self.iat + ACCESS_TOKEN_LIFETIME_SECONDS

    def as_claims(self) -> dict[str, Any]:
        """The JWT claim set, and nothing else.

        ``client_id_verified`` is ``False`` on every token, because the
        ``client_id`` beside it is whatever the browser typed at
        ``POST /device_authorization``: the marking ``POST /scan`` already puts
        in its response. No ``act``, no ``nbf``, no PII.
        """
        return {
            "iss": self.iss,
            "aud": self.aud,
            "sub": self.sub,
            "client_id": self.client_id,
            "client_id_verified": False,
            "scope": self.scope,
            "sid": self.sid,
            "jti": self.jti,
            "iat": self.iat,
            "exp": self.exp,
        }


class SessionTokenMinter:
    """Mints layer-1 access tokens over the SESSION key and no other."""

    def __init__(self, *, issuer: str, audience: str, key_source: KeySource) -> None:
        self._issuer = issuer
        self._audience = audience
        self._key_source = key_source

    def prepare(
        self, *, customer: CustomerRef, client_id: str, scope: str, sid: str
    ) -> SessionClaims:
        """Draw a ``jti`` and read the clock, once, and return frozen claims.

        The ``jti`` is ``uuid.uuid4()`` and is never accepted from a caller,
        for the reason ``InternalTokenMinter.mint_with_jti``'s docstring gives:
        a caller-chosen id is a collision someone else can arrange. ``sub``
        comes from a ``CustomerRef``, so a value that is not a customer
        reference cannot reach a token.
        """
        return SessionClaims(
            iss=self._issuer,
            aud=self._audience,
            sub=customer.value,
            client_id=client_id,
            scope=scope,
            sid=sid,
            jti=str(uuid.uuid4()),
            iat=int(time.time()),
        )

    def sign(self, claims: SessionClaims) -> str:
        """``claims`` as an RS256 compact JWS.

        Under Vault this is a transit request and can raise
        ``VaultTransitError``; it never returns an unsigned token.
        """
        return self._key_source.sign(claims.as_claims())


def build_session_minter(settings: ConfirmSettings) -> tuple[SessionTokenMinter, KeySource]:
    """The session minter plus the `KeySource` behind it, for the JWKS route.

    The same one-key-in, one-source-out call ``build_write_minter`` makes, so
    the SESSION key inherits every rule the other two keys have: Vault when
    ``POSTERN_VAULT_ADDR`` is set, a PEM when ``POSTERN_SESSION_KEY_PEM_PATH``
    is, a generated key with the ephemeral warning otherwise, and a refusal at
    startup when both are set.
    """
    key_source = choose_key_source(
        role="SESSION",
        kid=settings.session_key_kid,
        vault=settings.vault,
        vault_key_name=settings.vault_session_key_name,
        pem_path=settings.session_key_pem_path,
        pem_env_var="POSTERN_SESSION_KEY_PEM_PATH",
    )
    minter = SessionTokenMinter(
        issuer=settings.session_token_issuer,
        audience=settings.session_token_audience,
        key_source=key_source,
    )
    return minter, key_source
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `uv run pytest tests/test_confirm_auth.py tests/test_confirm_body_limit.py tests/test_confirm_rate_limit.py tests/test_ephemeral_key_warning.py tests/test_session_token.py -q`

Expected: 285 passed

- [ ] **Step 5: Format, then run the gate**

Run: `uv run ruff format packages services tests && make ci`

Expected: exit 0 (3576 passed at validation).

- [ ] **Step 6: Commit**

```bash
git add services/confirm/auth.py services/confirm/jwks.py services/confirm/main.py services/confirm/rate_limit.py services/confirm/session_token.py tests/test_confirm_auth.py tests/test_confirm_body_limit.py tests/test_confirm_rate_limit.py tests/test_ephemeral_key_warning.py tests/test_session_token.py
git commit -m "feat(confirm): a SESSION key, its minter and /session/jwks.json" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 3: Refresh-token families, on both backends

Spec section 4 in full: the `prt1.<sid>.<secret>` format, the record, the one pure verdict both backends call inside their transaction, the Redis layout (`SET NX EX`, `KEEPTTL`, the swept index), the cap and the rounded-up TTL. The store stamps `created_at` itself, from Redis `TIME` on Redis, because section 6 step 6 compares it with a revocation stamp written on that clock. Nothing wires it until Task 6.

**Files:**
- Create: `packages/postern-core/src/postern_core/auth/refresh_sessions.py` (the whole module)
- Create: `tests/test_refresh_sessions.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/test_refresh_sessions.py` with:

```python
"""The refresh-token family store, on both backends (spec section 4).

Every test runs twice: against `InMemoryRefreshSessionStore` and against
`RedisRefreshSessionStore` on the suite's Redis container, each in its own key
prefix. The verdict is one pure function both call, so the pair is also the
check that the Redis transaction wraps it the same way the dict does.
"""

from __future__ import annotations

import asyncio
import dataclasses
import time
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from postern_core.auth.refresh_sessions import (
    MAX_GENERATIONS,
    SESSION_ABSOLUTE_LIFETIME,
    InMemoryRefreshSessionStore,
    RedisRefreshSessionStore,
    RefreshSession,
    RefreshSessionCollision,
    RefreshSessionStoreBase,
    RefreshSessionStoreFull,
    Rotation,
    RotationOutcome,
    _ttl_seconds,
    canonical_scope,
    create_refresh_session_store,
    from_ms,
    hash_refresh_token,
    ms_of,
    new_refresh_token,
    new_sid,
    sid_of,
)

BACKENDS = ["memory", "redis"]


def _in(seconds: int) -> datetime:
    """Whole seconds from now, as an access token's ``exp`` always is."""
    return datetime.fromtimestamp(int(time.time()) + seconds, UTC)


async def _store(
    kind: str, request: pytest.FixtureRequest, max_sessions: int = 100
) -> RefreshSessionStoreBase:
    if kind == "memory":
        return InMemoryRefreshSessionStore(max_sessions=max_sessions)
    url = request.getfixturevalue("redis_url")
    return RedisRefreshSessionStore(
        url=url, key_prefix=f"rs{uuid4().hex[:12]}:", max_sessions=max_sessions
    )


@pytest.fixture(params=BACKENDS)
async def store(request: pytest.FixtureRequest) -> AsyncIterator[RefreshSessionStoreBase]:
    built = await _store(request.param, request)
    yield built
    await built.close()


def _family(sid: str | None = None, token: str | None = None) -> tuple[RefreshSession, str]:
    sid = sid or new_sid()
    token = token or new_refresh_token(sid)
    placeholder = datetime(2000, 1, 1, tzinfo=UTC)
    session = RefreshSession(
        sid=sid,
        customer_ref="cust_7f3a",
        client_id="claude-code",
        scopes="accounts:read cards:read",
        created_at=placeholder,
        expires_at=placeholder,
        generation=0,
        current_hash=hash_refresh_token(token),
        access_tokens=(("jti-0", _in(600)),),
        device_code_handle="0123456789abcdef",
    )
    return session, token


async def _rotate(
    store: RefreshSessionStoreBase, sid: str, presented: str, *, jti: str = "jti-next"
) -> tuple[RotationOutcome, str]:
    new = new_refresh_token(sid)
    outcome = await store.rotate(
        sid,
        presented_hash=hash_refresh_token(presented),
        new_hash=hash_refresh_token(new),
        access_jti=jti,
        access_expires_at=_in(600),
    )
    return outcome, new


class TestTheToken:
    def test_the_format_and_the_sid(self) -> None:
        sid = new_sid()
        token = new_refresh_token(sid)
        assert len(sid) == 22
        prefix, named, secret = token.split(".")
        assert prefix == "prt1"
        assert named == sid
        assert len(secret) == 43
        assert sid_of(token) == sid

    @pytest.mark.parametrize(
        "value",
        [
            "",
            "prt1..",
            "prt2." + "a" * 22 + "." + "b" * 43,
            "prt1." + "a" * 21 + "." + "b" * 43,
            "prt1." + "a" * 22 + "." + "b" * 42,
            "prt1." + "a" * 22 + "." + "b" * 43 + "x",
            "prt1." + "a" * 22 + "." + "b" * 42 + "=",
        ],
    )
    def test_a_malformed_value_names_no_family(self, value: str) -> None:
        assert sid_of(value) is None

    def test_the_hash_is_lowercase_sha256_hex_of_the_whole_value(self) -> None:
        digest = hash_refresh_token("prt1.x.y")
        assert len(digest) == 64
        assert digest == digest.lower()
        assert hash_refresh_token("prt1.x.z") != digest

    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            ("", ""),
            ("   ", ""),
            ("b a", "a b"),
            ("a  a b", "a b"),
            ("cards:read accounts:read", "accounts:read cards:read"),
            ("B a", "B a"),
        ],
    )
    def test_canonical_scope(self, value: str, expected: str) -> None:
        assert canonical_scope(value) == expected


class TestTheRecord:
    def test_milliseconds_round_trip_exactly(self) -> None:
        for value in (0, 1, 1_727_700_000_123, 1_727_700_000_999):
            assert ms_of(from_ms(value)) == value

    def test_json_round_trip(self) -> None:
        session, _ = _family()
        session = dataclasses.replace(
            session,
            created_at=from_ms(1_727_700_000_123),
            expires_at=from_ms(1_727_703_600_123),
            revoked_at=from_ms(1_727_700_100_000),
            revoked_reason="recall",
            retained_hashes=("a" * 64,),
        )
        assert RefreshSession.from_json(session.to_json()) == session

    def test_the_ttl_is_rounded_up(self) -> None:
        now = datetime(2026, 9, 30, 12, 0, 0, tzinfo=UTC)
        assert _ttl_seconds(now + timedelta(seconds=10, milliseconds=1), now) == 11
        assert _ttl_seconds(now + timedelta(seconds=10), now) == 10
        assert _ttl_seconds(now, now) == 1


class TestCreate:
    async def test_the_store_stamps_creation_and_the_absolute_expiry(
        self, store: RefreshSessionStoreBase
    ) -> None:
        session, _ = _family()
        before = datetime.now(UTC) - timedelta(seconds=5)
        stored = await store.create(session)
        assert stored.created_at >= before
        assert stored.expires_at - stored.created_at == SESSION_ABSOLUTE_LIFETIME
        assert await store.get(session.sid) == stored

    async def test_an_existing_sid_is_a_collision(self, store: RefreshSessionStoreBase) -> None:
        session, _ = _family()
        await store.create(session)
        with pytest.raises(RefreshSessionCollision):
            await store.create(session)

    @pytest.mark.parametrize("kind", BACKENDS)
    async def test_the_cap_refuses(self, kind: str, request: pytest.FixtureRequest) -> None:
        store = await _store(kind, request, max_sessions=2)
        await store.create(_family()[0])
        await store.create(_family()[0])
        with pytest.raises(RefreshSessionStoreFull):
            await store.create(_family()[0])
        await store.close()

    async def test_get_of_a_missing_sid_is_none(self, store: RefreshSessionStoreBase) -> None:
        assert await store.get(new_sid()) is None

    async def test_discard_deletes(self, store: RefreshSessionStoreBase) -> None:
        session, _ = _family()
        await store.create(session)
        await store.discard(session.sid)
        assert await store.get(session.sid) is None


class TestRotate:
    async def test_rotated_retains_the_old_hash_and_records_the_jti(
        self, store: RefreshSessionStoreBase
    ) -> None:
        session, token = _family()
        await store.create(session)
        outcome, new = await _rotate(store, session.sid, token, jti="jti-1")
        assert outcome.rotation is Rotation.ROTATED
        stored = await store.get(session.sid)
        assert stored is not None
        assert stored.generation == 1
        assert stored.current_hash == hash_refresh_token(new)
        assert stored.retained_hashes == (hash_refresh_token(token),)
        assert [jti for jti, _ in stored.access_tokens] == ["jti-0", "jti-1"]

    async def test_a_retained_token_is_reuse_and_revokes_in_the_same_transaction(
        self, store: RefreshSessionStoreBase
    ) -> None:
        session, token = _family()
        await store.create(session)
        _, new = await _rotate(store, session.sid, token, jti="jti-1")
        outcome, _ = await _rotate(store, session.sid, token)
        assert outcome.rotation is Rotation.REUSED
        assert set(outcome.jtis) == {"jti-0", "jti-1"}
        stored = await store.get(session.sid)
        assert stored is not None
        assert stored.revoked_at is not None
        assert stored.revoked_reason == "reuse"
        # The current token is now refused too: both parties lose the family.
        after, _ = await _rotate(store, session.sid, new)
        assert after.rotation is Rotation.REVOKED

    async def test_revoked_writes_nothing_and_returns_the_live_jtis(
        self, store: RefreshSessionStoreBase
    ) -> None:
        session, token = _family()
        await store.create(session)
        await store.revoke(session.sid, reason="recall")
        before = await store.get(session.sid)
        outcome, _ = await _rotate(store, session.sid, token)
        assert outcome.rotation is Rotation.REVOKED
        assert outcome.jtis == ("jti-0",)
        assert await store.get(session.sid) == before

    async def test_an_unknown_hash_writes_nothing(self, store: RefreshSessionStoreBase) -> None:
        session, _ = _family()
        stored = await store.create(session)
        outcome, _ = await _rotate(store, session.sid, new_refresh_token(session.sid))
        assert outcome.rotation is Rotation.UNKNOWN
        assert await store.get(session.sid) == stored

    async def test_exhausted_at_max_generations(self, store: RefreshSessionStoreBase) -> None:
        session, token = _family()
        await store.create(session)
        for _ in range(MAX_GENERATIONS):
            outcome, token = await _rotate(store, session.sid, token)
            assert outcome.rotation is Rotation.ROTATED
        stored = await store.get(session.sid)
        outcome, _ = await _rotate(store, session.sid, token)
        assert outcome.rotation is Rotation.EXHAUSTED
        assert await store.get(session.sid) == stored

    async def test_a_missing_family_is_gone(self, store: RefreshSessionStoreBase) -> None:
        outcome, _ = await _rotate(store, new_sid(), new_refresh_token(new_sid()))
        assert outcome.rotation is Rotation.GONE

    async def test_expired_access_tokens_are_pruned_on_write(
        self, store: RefreshSessionStoreBase
    ) -> None:
        session, token = _family()
        session = dataclasses.replace(session, access_tokens=(("old", _in(-1)),))
        await store.create(session)
        await _rotate(store, session.sid, token, jti="fresh")
        stored = await store.get(session.sid)
        assert stored is not None
        assert [jti for jti, _ in stored.access_tokens] == ["fresh"]

    async def test_two_concurrent_rotations_are_one_rotated_and_one_reused(
        self, store: RefreshSessionStoreBase
    ) -> None:
        session, token = _family()
        await store.create(session)
        results = await asyncio.gather(
            _rotate(store, session.sid, token, jti="a"),
            _rotate(store, session.sid, token, jti="b"),
        )
        rotations = sorted(r[0].rotation.value for r in results)
        assert rotations == ["reused", "rotated"]
        stored = await store.get(session.sid)
        assert stored is not None
        assert stored.revoked_reason == "reuse"


class TestRevoke:
    async def test_revoke_is_idempotent_and_keeps_the_first_reason(
        self, store: RefreshSessionStoreBase
    ) -> None:
        session, _ = _family()
        await store.create(session)
        first = await store.revoke(session.sid, reason="recall")
        second = await store.revoke(session.sid, reason="reuse")
        assert first == second == ("jti-0",)
        stored = await store.get(session.sid)
        assert stored is not None
        assert stored.revoked_reason == "recall"

    async def test_revoke_of_a_missing_family_is_none(self, store: RefreshSessionStoreBase) -> None:
        assert await store.revoke(new_sid(), reason="recall") is None


class TestRedisSpecifics:
    async def test_the_key_ttl_is_the_absolute_lifetime(self, redis_url: str) -> None:
        prefix = f"rs{uuid4().hex[:12]}:"
        store = RedisRefreshSessionStore(url=redis_url, key_prefix=prefix)
        session, _ = _family()
        await store.create(session)
        ttl = await store._redis.ttl(f"{prefix}refresh:session:{session.sid}")
        assert 3590 <= ttl <= 3600
        await _rotate(store, session.sid, _family(session.sid)[1])
        assert await store._redis.ttl(f"{prefix}refresh:session:{session.sid}") > 3590
        await store.close()

    async def test_an_undeserializable_record_is_gone(self, redis_url: str) -> None:
        prefix = f"rs{uuid4().hex[:12]}:"
        store = RedisRefreshSessionStore(url=redis_url, key_prefix=prefix)
        sid = new_sid()
        await store._redis.set(f"{prefix}refresh:session:{sid}", "{not json")
        assert await store.get(sid) is None
        outcome, _ = await _rotate(store, sid, new_refresh_token(sid))
        assert outcome.rotation is Rotation.GONE
        await store.close()

    async def test_creation_is_stamped_from_the_redis_clock(self, redis_url: str) -> None:
        store = RedisRefreshSessionStore(url=redis_url, key_prefix=f"rs{uuid4().hex[:12]}:")
        seconds, micros = await store._redis.time()
        stored = await store.create(_family()[0])
        assert abs(stored.created_ms - (int(seconds) * 1000 + int(micros) // 1000)) < 2000
        await store.close()


def test_the_factory_follows_the_redis_url(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("POSTERN_REDIS_URL", raising=False)
    assert isinstance(create_refresh_session_store(), InMemoryRefreshSessionStore)
    monkeypatch.setenv("POSTERN_REDIS_URL", "redis://127.0.0.1:1/0")
    assert isinstance(create_refresh_session_store(max_sessions=5), RedisRefreshSessionStore)
```

- [ ] **Step 2: Run them to verify they fail**

Run: `uv run pytest tests/test_refresh_sessions.py -q`

Expected: FAIL, `1 error`. The first failure reads `ModuleNotFoundError: No module named 'postern_core.auth.refresh_sessions'`.

- [ ] **Step 3: Implement**

Create `packages/postern-core/src/postern_core/auth/refresh_sessions.py` with:

```python
"""Refresh-token families for the layer-1 session token (spec section 4).

A SESSION FAMILY is everything issued from one device-code exchange: one
family id (``sid``), a chain of refresh tokens of which exactly one is
current, and the access tokens minted alongside. It lives at most
`SESSION_ABSOLUTE_LIFETIME` from the exchange, and nothing extends that.

THE REFRESH TOKEN IS ``prt1.<sid>.<secret>``. ``sid`` is 16 random bytes,
unpadded base64url (22 characters), and appears in every access token, so it
is NOT a secret: it only selects a record. ``secret`` is
``secrets.token_urlsafe(32)``, fresh per refresh token. The store keeps the
SHA-256 of the WHOLE token as lowercase hex and never the token, and every
action requires that hash to equal one the record holds. That is RFC 9700
section 4.14.2's integrity note: a known ``sid`` with any other secret matches
nothing, writes nothing and changes nothing.

ROTATION WITH REUSE DETECTION. Each refresh retires the presented token into
``retained_hashes`` and makes a new one current. A retained token presented
again means two parties hold one family, and the family is revoked in the same
transaction that noticed. The server cannot tell which party is the customer,
so both lose it -- RFC 9700's stated cost, which also falls on a client that
retries a refresh whose response it lost.

ONE PURE VERDICT, TWO BACKENDS. `_rotation_verdict` decides from the record
alone, the pattern `postern_core.auth.device_codes`'s ``_scan_verdict`` set, so
the in-memory and Redis stores cannot disagree about what a presentation earns.
The in-memory store is atomic by not yielding between its read and its write;
the Redis store makes the server settle it with ``WATCH``/``MULTI``.

TIMESTAMPS ARE MILLISECONDS. ``created_at`` is compared with
`postern_core.auth.revocation`'s ``customer_revoked_at``, which is integer
milliseconds, so the record keeps the creation instant exactly at that
resolution (`RefreshSession.created_ms`). The store stamps it: Redis ``TIME``
on the Redis backend, the one clock the revocation stamp is written with, and
``time.time_ns()`` in memory.
"""

from __future__ import annotations

import dataclasses
import enum
import hashlib
import hmac
import json
import logging
import math
import os
import re
import secrets
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

logger = logging.getLogger(__name__)

#: How long a family lives from its exchange. Absolute: rotation does not move
#: it. One hour, not the twelve first approved, until the per-family app
#: notification exists (spec, "What this does not fix").
SESSION_ABSOLUTE_LIFETIME = timedelta(hours=1)

#: Rotations one family may make. One hour at one refresh per 10-minute
#: access token is 6; 64 admits a client refreshing about once a minute, and
#: bounds ``retained_hashes`` at 64 hashes of 64 characters, about 4 KiB.
MAX_GENERATIONS = 64

#: The default of ``POSTERN_MAX_REFRESH_SESSIONS``: `postern_core.auth.device_codes`'s
#: ``DEFAULT_MAX_DEVICE_CODES`` times the lifetime ratio (3,600 s / 900 s).
DEFAULT_MAX_REFRESH_SESSIONS = 40_000

#: Random bytes behind a family id: 128 bits, 22 base64url characters.
SID_BYTES = 16

#: The refresh token's version prefix.
REFRESH_TOKEN_PREFIX = "prt1"  # noqa: S105 -- a format tag, not a credential

#: The whole refresh token, anchored. 22 characters of ``sid`` and 43 of
#: secret are what ``secrets.token_urlsafe`` produces for 16 and 32 bytes.
REFRESH_TOKEN_PATTERN = re.compile(r"prt1\.([A-Za-z0-9_-]{22})\.([A-Za-z0-9_-]{43})")

#: How many times a Redis compare-and-set re-reads a record another writer
#: moved under its ``WATCH`` before it gives up, as
#: `postern_core.auth.device_codes`'s ``_CLAIM_ATTEMPTS`` does.
_CLAIM_ATTEMPTS = 3

_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)


class RefreshSessionStoreFull(RuntimeError):
    """The store holds ``max_sessions`` live families after sweeping."""

    def __init__(self, held: int, cap: int) -> None:
        super().__init__(f"refresh session store holds {held} families, at its cap of {cap}")
        self.held = held
        self.cap = cap


class RefreshSessionStoreContended(RuntimeError):
    """A compare-and-set was beaten by another writer on every attempt."""


class RefreshSessionCollision(RuntimeError):
    """``create`` was handed a ``sid`` the store already holds: 128 bits collided."""


class Rotation(enum.Enum):
    """What one presentation of a refresh token earned."""

    ROTATED = "rotated"
    REUSED = "reused"
    REVOKED = "revoked"
    UNKNOWN = "unknown"
    EXHAUSTED = "exhausted"
    GONE = "gone"


def ms_of(instant: datetime) -> int:
    """``instant`` as integer milliseconds since the Unix epoch, exactly."""
    return (instant - _EPOCH) // timedelta(milliseconds=1)


def from_ms(value: int) -> datetime:
    """Inverse of `ms_of`."""
    return _EPOCH + timedelta(milliseconds=value)


def now_ms() -> int:
    """This process's clock in milliseconds, for the in-memory backends."""
    return time.time_ns() // 1_000_000


def new_sid() -> str:
    """A fresh family id."""
    return secrets.token_urlsafe(SID_BYTES)


def new_refresh_token(sid: str) -> str:
    """A fresh refresh token for family ``sid``."""
    return f"{REFRESH_TOKEN_PREFIX}.{sid}.{secrets.token_urlsafe(32)}"


def hash_refresh_token(token: str) -> str:
    """SHA-256 of the whole presented value, lowercase hex."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def sid_of(presented: str) -> str | None:
    """The family id a well-formed refresh token names, or ``None``."""
    match = REFRESH_TOKEN_PATTERN.fullmatch(presented)
    return match.group(1) if match else None


def canonical_scope(value: str) -> str:
    """Split on ASCII space, drop empties and duplicates, sort by code point, join.

    Spec section 6 step 5. Used for a family's ``scopes``, for every ``scope``
    claim, and for comparing a requested scope with the granted one.
    """
    return " ".join(sorted({part for part in value.split(" ") if part}))


@dataclass(frozen=True)
class RefreshSession:
    """One family, as the store holds it. Never carries a token."""

    sid: str
    customer_ref: str
    client_id: str
    scopes: str
    created_at: datetime
    expires_at: datetime
    generation: int
    current_hash: str
    retained_hashes: tuple[str, ...] = ()
    access_tokens: tuple[tuple[str, datetime], ...] = ()
    revoked_at: datetime | None = None
    revoked_reason: str = ""
    device_code_handle: str = ""

    @property
    def created_ms(self) -> int:
        """``created_at`` in integer milliseconds, the resolution revocation compares at."""
        return ms_of(self.created_at)

    def is_expired(self, now: datetime) -> bool:
        return now >= self.expires_at

    def live_jtis(self, now: datetime) -> tuple[str, ...]:
        """The ``jti`` of every access token of this family not yet expired."""
        return tuple(jti for jti, exp in self.access_tokens if exp > now)

    def to_json(self) -> str:
        return json.dumps(
            {
                "sid": self.sid,
                "customer_ref": self.customer_ref,
                "client_id": self.client_id,
                "scopes": self.scopes,
                "created_at_ms": ms_of(self.created_at),
                "expires_at_ms": ms_of(self.expires_at),
                "generation": self.generation,
                "current_hash": self.current_hash,
                "retained_hashes": list(self.retained_hashes),
                "access_tokens": [[jti, ms_of(exp)] for jti, exp in self.access_tokens],
                "revoked_at_ms": ms_of(self.revoked_at) if self.revoked_at else None,
                "revoked_reason": self.revoked_reason,
                "device_code_handle": self.device_code_handle,
            },
            separators=(",", ":"),
        )

    @classmethod
    def from_json(cls, raw: str) -> RefreshSession:
        data = json.loads(raw)
        revoked = data.get("revoked_at_ms")
        return cls(
            sid=str(data["sid"]),
            customer_ref=str(data["customer_ref"]),
            client_id=str(data["client_id"]),
            scopes=str(data["scopes"]),
            created_at=from_ms(int(data["created_at_ms"])),
            expires_at=from_ms(int(data["expires_at_ms"])),
            generation=int(data["generation"]),
            current_hash=str(data["current_hash"]),
            retained_hashes=tuple(str(h) for h in data["retained_hashes"]),
            access_tokens=tuple((str(j), from_ms(int(e))) for j, e in data["access_tokens"]),
            revoked_at=from_ms(int(revoked)) if revoked is not None else None,
            revoked_reason=str(data.get("revoked_reason", "")),
            device_code_handle=str(data.get("device_code_handle", "")),
        )


@dataclass(frozen=True)
class RotationOutcome:
    """What `RefreshSessionStoreBase.rotate` decided, and what it saw.

    ``session`` is the record as the transaction left it (``None`` for
    ``GONE`` on a missing or unreadable record), so a caller answering a
    non-``ROTATED`` result can re-run its own classification against exactly
    what the store saw. ``jtis`` are the family's unexpired access-token ids
    for ``REUSED`` and ``REVOKED``, and empty otherwise.
    """

    rotation: Rotation
    session: RefreshSession | None = None
    jtis: tuple[str, ...] = ()


def _stamped(session: RefreshSession, created_ms: int) -> RefreshSession:
    """``session`` with the store's own clock as its creation instant."""
    created = from_ms(created_ms)
    return dataclasses.replace(
        session, created_at=created, expires_at=created + SESSION_ABSOLUTE_LIFETIME
    )


def _pruned(
    tokens: tuple[tuple[str, datetime], ...], now: datetime
) -> tuple[tuple[str, datetime], ...]:
    return tuple((jti, exp) for jti, exp in tokens if exp > now)


def _is_current(session: RefreshSession, presented_hash: str) -> bool:
    return hmac.compare_digest(session.current_hash, presented_hash)


def _rotation_verdict(session: RefreshSession, presented_hash: str, now: datetime) -> Rotation:
    """The one decision both backends make inside their transaction.

    POSSESSION FIRST. A hash this family never issued is ``UNKNOWN`` in every
    state the family can be in, so a caller holding a ``sid`` and a guessed
    secret learns nothing, not even that the family is revoked (RFC 9700
    section 4.14.2). Then revoked, so a revoked family answers the same to
    every token it issued. Then a retained hash, which is reuse. Then the
    two ends of life.
    """
    retained = presented_hash in session.retained_hashes
    if not retained and not _is_current(session, presented_hash):
        return Rotation.UNKNOWN
    if session.revoked_at is not None:
        return Rotation.REVOKED
    if retained:
        return Rotation.REUSED
    if session.generation >= MAX_GENERATIONS:
        return Rotation.EXHAUSTED
    if session.is_expired(now):
        return Rotation.GONE
    return Rotation.ROTATED


def _revoked(session: RefreshSession, reason: str, now: datetime) -> RefreshSession:
    """``session`` revoked, keeping the first reason, pruned."""
    if session.revoked_at is not None:
        return dataclasses.replace(session, access_tokens=_pruned(session.access_tokens, now))
    return dataclasses.replace(
        session,
        revoked_at=now,
        revoked_reason=reason,
        access_tokens=_pruned(session.access_tokens, now),
    )


def _rotated(
    session: RefreshSession,
    new_hash: str,
    access_jti: str,
    access_expires_at: datetime,
    now: datetime,
) -> RefreshSession:
    return dataclasses.replace(
        session,
        generation=session.generation + 1,
        retained_hashes=(*session.retained_hashes, session.current_hash),
        current_hash=new_hash,
        access_tokens=(*_pruned(session.access_tokens, now), (access_jti, access_expires_at)),
    )


def _decide(
    session: RefreshSession,
    *,
    presented_hash: str,
    new_hash: str,
    access_jti: str,
    access_expires_at: datetime,
    now: datetime,
) -> tuple[RotationOutcome, RefreshSession | None]:
    """The verdict and the record to write, or ``None`` when nothing is written."""
    verdict = _rotation_verdict(session, presented_hash, now)
    if verdict is Rotation.ROTATED:
        written = _rotated(session, new_hash, access_jti, access_expires_at, now)
        return RotationOutcome(verdict, written), written
    if verdict is Rotation.REUSED:
        written = _revoked(session, "reuse", now)
        return RotationOutcome(verdict, written, written.live_jtis(now)), written
    if verdict is Rotation.REVOKED:
        return RotationOutcome(verdict, session, session.live_jtis(now)), None
    return RotationOutcome(verdict, session), None


class RefreshSessionStoreBase(ABC):
    """The family store, in whichever backend. Async throughout."""

    @abstractmethod
    async def create(self, session: RefreshSession) -> RefreshSession:
        """Store a new family and return it as stored.

        The store STAMPS ``created_at`` from its own clock and sets
        ``expires_at`` to that plus `SESSION_ABSOLUTE_LIFETIME`; the values on
        ``session`` are replaced. Sweeps expired families first, then raises
        `RefreshSessionStoreFull` at the cap. An existing ``sid`` raises
        `RefreshSessionCollision`.
        """

    @abstractmethod
    async def get(self, sid: str) -> RefreshSession | None:
        """The live family, or ``None`` for missing, expired or undeserializable."""

    @abstractmethod
    async def discard(self, sid: str) -> None:
        """Delete a family nobody holds a token for (spec section 5 step 3)."""

    @abstractmethod
    async def rotate(
        self,
        sid: str,
        *,
        presented_hash: str,
        new_hash: str,
        access_jti: str,
        access_expires_at: datetime,
    ) -> RotationOutcome:
        """One compare-and-set deciding with `_rotation_verdict`.

        ``ROTATED`` retains the presented hash, makes ``new_hash`` current,
        increments ``generation`` and records the new access ``jti``.
        ``REUSED`` revokes the family with reason ``reuse`` in the same
        transaction. Every other result writes nothing.
        """

    @abstractmethod
    async def revoke(self, sid: str, *, reason: str) -> tuple[str, ...] | None:
        """Revoke a family, keeping the first reason; its unexpired jtis, or ``None``."""

    async def close(self) -> None:  # noqa: B027 - concrete and empty on purpose
        """Release any connection this store holds. A no-op by default."""
        return None


class InMemoryRefreshSessionStore(RefreshSessionStoreBase):
    """Per process. ``create_confirm_app`` refuses it without the dev flag.

    Atomic by not yielding: no method below awaits between its read and its
    write, which is the whole implementation of its compare-and-set.
    """

    def __init__(self, max_sessions: int = DEFAULT_MAX_REFRESH_SESSIONS) -> None:
        self._sessions: dict[str, RefreshSession] = {}
        self._max_sessions = max_sessions

    def _sweep(self, now: datetime) -> None:
        for sid in [sid for sid, s in self._sessions.items() if s.is_expired(now)]:
            del self._sessions[sid]

    async def create(self, session: RefreshSession) -> RefreshSession:
        stamped = _stamped(session, now_ms())
        self._sweep(datetime.now(UTC))
        if len(self._sessions) >= self._max_sessions:
            raise RefreshSessionStoreFull(len(self._sessions), self._max_sessions)
        if session.sid in self._sessions:
            raise RefreshSessionCollision(f"family {session.sid} already exists")
        self._sessions[session.sid] = stamped
        return stamped

    async def get(self, sid: str) -> RefreshSession | None:
        session = self._sessions.get(sid)
        if session is None or session.is_expired(datetime.now(UTC)):
            return None
        return session

    async def discard(self, sid: str) -> None:
        self._sessions.pop(sid, None)

    async def rotate(
        self,
        sid: str,
        *,
        presented_hash: str,
        new_hash: str,
        access_jti: str,
        access_expires_at: datetime,
    ) -> RotationOutcome:
        session = self._sessions.get(sid)
        if session is None:
            return RotationOutcome(Rotation.GONE)
        outcome, written = _decide(
            session,
            presented_hash=presented_hash,
            new_hash=new_hash,
            access_jti=access_jti,
            access_expires_at=access_expires_at,
            now=datetime.now(UTC),
        )
        if written is not None:
            self._sessions[sid] = written
        return outcome

    async def revoke(self, sid: str, *, reason: str) -> tuple[str, ...] | None:
        session = self._sessions.get(sid)
        if session is None:
            return None
        now = datetime.now(UTC)
        written = _revoked(session, reason, now)
        self._sessions[sid] = written
        return written.live_jtis(now)


def _ttl_seconds(expires_at: datetime, now: datetime) -> int:
    """Seconds until ``expires_at``, rounded UP.

    Truncation shortened device codes by up to a second (bug B1, in
    `postern_core.auth.device_codes`'s ``MIN_DEVICE_CODE_TTL_SECONDS``
    commentary); a family must not lose its last second the same way. Every
    read re-checks ``expires_at`` anyway, so the key outliving the record by
    under a second is harmless.
    """
    return max(1, math.ceil((expires_at - now).total_seconds()))


class RedisRefreshSessionStore(RefreshSessionStoreBase):
    """Families in Redis, shared by every replica.

    ``{prefix}refresh:session:<sid>`` holds the JSON record with a TTL set by
    ``create`` (``SET NX EX``) and kept by every later write (``KEEPTTL``).
    ``{prefix}refresh:index`` is a sorted set of ``sid`` scored by expiry,
    swept on ``create`` and counted for the cap, the shape
    `postern_core.auth.device_codes`'s ``RedisDeviceCodeStore`` uses and for
    its reasons.
    """

    def __init__(
        self,
        url: str | None = None,
        key_prefix: str | None = None,
        max_sessions: int = DEFAULT_MAX_REFRESH_SESSIONS,
    ) -> None:
        import redis.asyncio as redis

        self._url = url or os.environ.get("POSTERN_REDIS_URL", "redis://localhost:6379/0")
        self._prefix = key_prefix or os.environ.get("POSTERN_REDIS_KEY_PREFIX", "postern:")
        self._max_sessions = max_sessions
        self._redis: Any = redis.from_url(  # type: ignore[no-untyped-call]
            self._url, decode_responses=True
        )

    def _key(self, sid: str) -> str:
        return f"{self._prefix}refresh:session:{sid}"

    @property
    def _index_key(self) -> str:
        return f"{self._prefix}refresh:index"

    async def _server_ms(self) -> int:
        """Redis ``TIME`` in milliseconds: the clock the revocation stamp uses."""
        seconds, microseconds = await self._redis.time()
        return int(seconds) * 1000 + int(microseconds) // 1000

    async def create(self, session: RefreshSession) -> RefreshSession:
        created_ms = await self._server_ms()
        stamped = _stamped(session, created_ms)
        now = from_ms(created_ms)
        pipe = self._redis.pipeline()
        pipe.zremrangebyscore(self._index_key, "-inf", created_ms / 1000)
        pipe.zcard(self._index_key)
        dropped, held = await pipe.execute()
        if dropped:
            logger.info("refresh session store: swept %d expired families", dropped)
        if held >= self._max_sessions:
            raise RefreshSessionStoreFull(int(held), self._max_sessions)
        written = await self._redis.set(
            self._key(session.sid),
            stamped.to_json(),
            nx=True,
            ex=_ttl_seconds(stamped.expires_at, now),
        )
        if not written:
            raise RefreshSessionCollision(f"family {session.sid} already exists")
        await self._redis.zadd(self._index_key, {session.sid: ms_of(stamped.expires_at) / 1000})
        return stamped

    def _parse(self, sid: str, raw: str | None) -> RefreshSession | None:
        if raw is None:
            return None
        try:
            return RefreshSession.from_json(raw)
        except (KeyError, ValueError, TypeError):
            logger.warning("refresh session %s will not deserialize; treating it as gone", sid)
            return None

    async def get(self, sid: str) -> RefreshSession | None:
        session = self._parse(sid, await self._redis.get(self._key(sid)))
        if session is None or session.is_expired(datetime.now(UTC)):
            return None
        return session

    async def discard(self, sid: str) -> None:
        pipe = self._redis.pipeline()
        pipe.delete(self._key(sid))
        pipe.zrem(self._index_key, sid)
        await pipe.execute()

    async def rotate(
        self,
        sid: str,
        *,
        presented_hash: str,
        new_hash: str,
        access_jti: str,
        access_expires_at: datetime,
    ) -> RotationOutcome:
        from redis.exceptions import WatchError

        key = self._key(sid)
        for _ in range(_CLAIM_ATTEMPTS):
            async with self._redis.pipeline(transaction=True) as pipe:
                try:
                    await pipe.watch(key)
                    session = self._parse(sid, await pipe.get(key))
                    if session is None:
                        return RotationOutcome(Rotation.GONE)
                    outcome, written = _decide(
                        session,
                        presented_hash=presented_hash,
                        new_hash=new_hash,
                        access_jti=access_jti,
                        access_expires_at=access_expires_at,
                        now=datetime.now(UTC),
                    )
                    if written is not None:
                        pipe.multi()
                        pipe.set(key, written.to_json(), keepttl=True)
                        await pipe.execute()
                    return outcome
                except WatchError:
                    continue
        raise RefreshSessionStoreContended(
            f"a refresh of family {sid} was beaten by another writer {_CLAIM_ATTEMPTS} times"
        )

    async def revoke(self, sid: str, *, reason: str) -> tuple[str, ...] | None:
        from redis.exceptions import WatchError

        key = self._key(sid)
        for _ in range(_CLAIM_ATTEMPTS):
            async with self._redis.pipeline(transaction=True) as pipe:
                try:
                    await pipe.watch(key)
                    session = self._parse(sid, await pipe.get(key))
                    if session is None:
                        return None
                    now = datetime.now(UTC)
                    written = _revoked(session, reason, now)
                    pipe.multi()
                    pipe.set(key, written.to_json(), keepttl=True)
                    await pipe.execute()
                    return written.live_jtis(now)
                except WatchError:
                    continue
        raise RefreshSessionStoreContended(
            f"a revocation of family {sid} was beaten by another writer {_CLAIM_ATTEMPTS} times"
        )

    async def close(self) -> None:
        await self._redis.aclose()


def create_refresh_session_store(
    max_sessions: int = DEFAULT_MAX_REFRESH_SESSIONS,
) -> RefreshSessionStoreBase:
    """A Redis store when ``POSTERN_REDIS_URL`` is set, else an in-memory one.

    The same choice `postern_core.auth.device_codes.create_device_code_store`
    makes, on the same variable, so one URL points every store at one Redis.
    """
    redis_url = os.environ.get("POSTERN_REDIS_URL")
    if redis_url:
        logger.info("Using Redis refresh session store")
        return RedisRefreshSessionStore(url=redis_url, max_sessions=max_sessions)
    logger.info("Using in-memory refresh session store (set POSTERN_REDIS_URL for Redis)")
    return InMemoryRefreshSessionStore(max_sessions=max_sessions)
```

> **Amended 1 October 2026, after review of the Task 3 commit.** The verdict above now proves possession first: a hash the family never issued is `UNKNOWN` even on a revoked family, where it used to be `REVOKED` with the family's live jtis. Task 7's handler is unaffected, because it checks possession itself (spec section 6 step 3) before it calls `rotate`. The committed module also differs from this block in three ways the block does not repeat: `current_hash` and `retained_hashes` are `field(repr=False)`, the module docstring records the accepted Redis residuals (see Concerns), and the test file adds a possession test, a repr test, two WATCH-contention tests for `rotate` and two for `revoke` (one of them pinning that a revoke losing its WATCH to a rotation keeps the rotation's new jti), a forced-interleaving counter on the concurrency test, and a TTL test that rotates with the family's own token. Steps 4 and 5 carry the amended counts.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `uv run pytest tests/test_refresh_sessions.py -q`

Expected: 59 passed (52 as first written; the 1 October amendment adds 7)

- [ ] **Step 5: Format, then run the gate**

Run: `uv run ruff format packages services tests && make ci`

Expected: exit 0 (3628 passed at validation, before the 1 October amendment's 7 tests; the validation table below records the same pre-amendment measurement).

- [ ] **Step 6: Commit**

```bash
git add packages/postern-core/src/postern_core/auth/refresh_sessions.py tests/test_refresh_sessions.py
git commit -m "feat(core): refresh-token families with rotation and reuse detection" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 4: The customer revocation stamp, in milliseconds

Spec section 6 step 6's store change: `customer_revoked_at` on both revocation backends, written by one Lua script with the pair's `SADD` on Redis's own clock, kept after a restore, and expiring after `CUSTOMER_REVOKED_AT_TTL_SECONDS` (4,800). `ConfirmSettings.from_env` then refuses a device-code lifetime the stamp cannot cover (above 900 seconds). `revoke_cli` needs no change. The two ZT-7 test fixtures that faked Redis with `fakeredis` move to the real container, because `fakeredis` without `lupa` has no `EVAL` (Verified facts).

**Files:**
- Modify: `packages/postern-core/src/postern_core/auth/revocation.py` (`CUSTOMER_REVOKED_AT_TTL_SECONDS`, `_REVOKE_CUSTOMER_CLIENT`, `customer_revoked_at` on the base and both backends)
- Modify: `services/confirm/settings.py` (`MAX_DEVICE_CODE_TTL_SECONDS`, `_device_code_ttl`)
- Create: `tests/test_customer_revoked_at.py`
- Modify: `tests/test_device_grant.py`
- Modify: `tests/test_settings_bounds.py`
- Modify: `tests/test_zt7_confirm_revocation.py` (`shared_redis`)
- Modify: `tests/test_zt7_revocation_reachable.py` (`shared_redis`)

- [ ] **Step 1: Write the failing tests**

Create `tests/test_customer_revoked_at.py` with:

```python
"""``customer_revoked_at``: when a customer was last cut off, in milliseconds.

Spec section 6 step 6 of ``dev-docs/device-grant-session-token-spec.md``. The
stamp is what lets ``POST /token`` refuse a refresh family or an approval that
predates a revocation even after the revocation is restored, so it must
survive the restore, be written in the same step as the pair, and expire after
`CUSTOMER_REVOKED_AT_TTL_SECONDS`. Both backends, against the suite's Redis.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import AsyncIterator
from typing import Any
from uuid import uuid4

import pytest
from postern_core.auth import revocation
from postern_core.auth.revocation import (
    CUSTOMER_REVOKED_AT_TTL_SECONDS,
    InMemoryRevocationStore,
    RedisRevocationStore,
    RevocationSnapshot,
    RevocationStoreBase,
    RevocationStoreUnavailable,
)

from services.confirm.settings import MAX_DEVICE_CODE_TTL_SECONDS

CUSTOMER = "cust_7f3a"


@pytest.fixture(params=["memory", "redis"])
async def store(request: pytest.FixtureRequest) -> AsyncIterator[RevocationStoreBase]:
    built: RevocationStoreBase
    if request.param == "memory":
        built = InMemoryRevocationStore()
    else:
        built = RedisRevocationStore(
            url=request.getfixturevalue("redis_url"), key_prefix=f"ra{uuid4().hex[:12]}:"
        )
    yield built
    await built.close()


def test_the_ttl_is_the_family_plus_the_device_code_plus_a_margin() -> None:
    assert CUSTOMER_REVOKED_AT_TTL_SECONDS == 3_600 + 900 + 300
    assert MAX_DEVICE_CODE_TTL_SECONDS == 900


async def test_never_revoked_is_none(store: RevocationStoreBase) -> None:
    assert await store.customer_revoked_at(CUSTOMER) is None


async def test_the_stamp_is_milliseconds_and_survives_a_restore(
    store: RevocationStoreBase,
) -> None:
    before = time.time_ns() // 1_000_000
    await store.revoke_customer_client(customer_ref=CUSTOMER, client_id="vendor-x")
    stamp = await store.customer_revoked_at(CUSTOMER)
    assert stamp is not None
    assert abs(stamp - before) < 2_000, "milliseconds, from a clock near this one"
    await store.restore_customer_client(customer_ref=CUSTOMER, client_id="vendor-x")
    assert await store.is_customer_revoked(CUSTOMER) is False
    assert await store.customer_revoked_at(CUSTOMER) == stamp


async def test_a_later_revocation_overwrites_the_stamp(store: RevocationStoreBase) -> None:
    await store.revoke_customer_client(customer_ref=CUSTOMER, client_id="vendor-x")
    first = await store.customer_revoked_at(CUSTOMER)
    await asyncio.sleep(0.01)
    await store.revoke_customer_client(customer_ref=CUSTOMER, client_id="vendor-y")
    second = await store.customer_revoked_at(CUSTOMER)
    assert first is not None and second is not None
    assert second > first


async def test_the_stamp_names_only_its_customer(store: RevocationStoreBase) -> None:
    await store.revoke_customer_client(customer_ref=CUSTOMER, client_id="vendor-x")
    assert await store.customer_revoked_at("cust_other") is None


async def test_session_and_kill_switch_revocations_do_not_stamp(
    store: RevocationStoreBase,
) -> None:
    await store.revoke_session(jti="tok-1")
    await store.kill_switch(client_id="vendor-x")
    assert await store.customer_revoked_at(CUSTOMER) is None


async def test_the_redis_script_writes_the_pair_and_the_stamp_on_redis_time(
    redis_url: str,
) -> None:
    prefix = f"ra{uuid4().hex[:12]}:"
    store = RedisRevocationStore(url=redis_url, key_prefix=prefix)
    seconds, micros = await store._redis.time()
    server_ms = int(seconds) * 1000 + int(micros) // 1000
    await store.revoke_customer_client(customer_ref=CUSTOMER, client_id="vendor-x")
    assert await store.is_customer_revoked(CUSTOMER) is True
    stamp = await store.customer_revoked_at(CUSTOMER)
    assert stamp is not None
    assert 0 <= stamp - server_ms < 2_000
    ttl = await store._redis.ttl(f"{prefix}revoked:customer-at:{CUSTOMER}")
    assert CUSTOMER_REVOKED_AT_TTL_SECONDS - 5 <= ttl <= CUSTOMER_REVOKED_AT_TTL_SECONDS
    await store.close()


async def test_the_in_memory_stamp_expires_after_the_ttl(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = InMemoryRevocationStore()
    clock = {"ms": 1_000_000}
    monkeypatch.setattr(revocation, "_now_ms", lambda: clock["ms"])
    await store.revoke_customer_client(customer_ref=CUSTOMER, client_id="vendor-x")
    clock["ms"] += CUSTOMER_REVOKED_AT_TTL_SECONDS * 1000 - 1
    assert await store.customer_revoked_at(CUSTOMER) == 1_000_000
    clock["ms"] += 1
    assert await store.customer_revoked_at(CUSTOMER) is None


async def test_an_unreachable_redis_is_unavailable_not_none() -> None:
    store = RedisRevocationStore(url="redis://127.0.0.1:1/0", key_prefix="unreachable:")
    with pytest.raises(RevocationStoreUnavailable):
        await store.customer_revoked_at(CUSTOMER)
    with pytest.raises(RevocationStoreUnavailable):
        await store.revoke_customer_client(customer_ref=CUSTOMER, client_id="vendor-x")
    await store.close()


async def test_a_double_that_implements_only_the_abstract_methods_answers_none() -> None:
    class Minimal(RevocationStoreBase):
        async def is_revoked(self, claims: Any) -> bool:
            return False

        async def revoke_session(self, *, jti: str) -> None: ...

        async def restore_session(self, *, jti: str) -> None: ...

        async def revoke_customer_client(self, *, customer_ref: str, client_id: str) -> None: ...

        async def restore_customer_client(self, *, customer_ref: str, client_id: str) -> None: ...

        async def kill_switch(self, *, client_id: str) -> None: ...

        async def restore_client(self, *, client_id: str) -> None: ...

        async def entries(self) -> RevocationSnapshot:
            return RevocationSnapshot()

    assert await Minimal().customer_revoked_at(CUSTOMER) is None
```

In `tests/test_device_grant.py`, replace:

```python

    @pytest.mark.parametrize("raised", ["31", "300", "900", "1800", "3600"])
    def test_a_value_at_or_above_the_floor_is_read_from_the_environment(
```

with:

```python

    @pytest.mark.parametrize("raised", ["31", "300", "900"])
    def test_a_value_at_or_above_the_floor_is_read_from_the_environment(
```

In `tests/test_device_grant.py`, replace:

```python
        assert ConfirmSettings.from_env().device_code_ttl_seconds == int(raised)

```

with:

```python
        assert ConfirmSettings.from_env().device_code_ttl_seconds == int(raised)

    @pytest.mark.parametrize("too_long", ["901", "1800", "3600"])
    def test_a_value_above_the_revocation_stamp_ceiling_refuses_at_startup(
        self, monkeypatch: pytest.MonkeyPatch, too_long: str
    ) -> None:
        """An approved code must not outlive the customer revocation stamp
        ``POST /token`` compares its approval with: 4,800 seconds less the
        one-hour family and a 300-second margin is 900."""
        monkeypatch.setenv("POSTERN_DEVICE_CODE_TTL_SECONDS", too_long)
        with pytest.raises(ValueError, match="must be at most 900 seconds"):
            ConfirmSettings.from_env()

```

In `tests/test_settings_bounds.py`, replace:

```python
        900,
        ("0", "1", "29", "-1"),
        (str(MIN_DEVICE_CODE_TTL_SECONDS), "900"),
```

with:

```python
        900,
        ("0", "1", "29", "-1", "901", "3600"),
        (str(MIN_DEVICE_CODE_TTL_SECONDS), "900"),
```

In `tests/test_zt7_confirm_revocation.py`, replace:

```python
from unittest.mock import patch

```

with:

```python
from unittest.mock import patch
from uuid import uuid4

```

In `tests/test_zt7_confirm_revocation.py`, replace:

```python
@pytest.fixture
def shared_redis(monkeypatch: pytest.MonkeyPatch) -> Iterator[Any]:
    """One ``fakeredis`` server standing in for the deployment's Redis.

    Every store built while this is active -- by either confirm app, and by
    the CLI on its own thread and its own event loop -- calls the patched
    ``redis.asyncio.from_url`` and lands on this one server. That is what makes
    the two apps below genuinely two replicas of one deployment rather than two
    objects sharing a reference. Copied deliberately from
    ``tests/test_zt7_revocation_reachable.py`` rather than promoted to
    ``conftest.py``: that file's fixture is the read path's and the two must be
    free to diverge.
    """
    import fakeredis
    import fakeredis.aioredis
    import redis.asyncio

    server = fakeredis.FakeServer()

    def _from_url(url: str, **kwargs: Any) -> Any:
        return fakeredis.aioredis.FakeRedis(server=server, **kwargs)

    monkeypatch.setattr(redis.asyncio, "from_url", _from_url)
    monkeypatch.setenv("POSTERN_REDIS_URL", "redis://fake.test:6379/0")
    yield server

```

with:

```python
@pytest.fixture
def shared_redis(monkeypatch: pytest.MonkeyPatch, redis_url: str) -> Iterator[Any]:
    """The suite's Redis standing in for the deployment's, in a prefix of its own.

    Every store built while this is active -- by either confirm app, and by
    the CLI on its own thread and its own event loop -- reads
    ``POSTERN_REDIS_URL`` and ``POSTERN_REDIS_KEY_PREFIX`` and lands on this
    one key space. That is what makes the two apps below genuinely two replicas
    of one deployment rather than two objects sharing a reference. Copied
    deliberately from ``tests/test_zt7_revocation_reachable.py`` rather than
    promoted to ``conftest.py``: that file's fixture is the read path's and the
    two must be free to diverge.

    A ``fakeredis`` server until the layer-1 session token: a customer-client
    revocation is now one Lua script (``EVAL``), and fakeredis 2.38.0 without
    ``lupa`` answers "unknown command 'eval'".
    """
    monkeypatch.setenv("POSTERN_REDIS_URL", redis_url)
    monkeypatch.setenv("POSTERN_REDIS_KEY_PREFIX", f"zt7c{uuid4().hex[:12]}:")
    yield redis_url

```

In `tests/test_zt7_revocation_reachable.py`, replace:

```python
from typing import Any

```

with:

```python
from typing import Any
from uuid import uuid4

```

In `tests/test_zt7_revocation_reachable.py`, replace:

```python
@pytest.fixture
def shared_redis(monkeypatch: pytest.MonkeyPatch) -> Iterator[Any]:
    """One `fakeredis` server standing in for the deployment's Redis.

```

with:

```python
@pytest.fixture
def shared_redis(monkeypatch: pytest.MonkeyPatch, redis_url: str) -> Iterator[Any]:
    """The suite's Redis standing in for the deployment's, in a prefix of its own.

```

In `tests/test_zt7_revocation_reachable.py`, replace:

```python
    instance, and by the CLI running in its own thread and its own event loop
    -- calls the patched `redis.asyncio.from_url` and lands on this one
    server. That is what makes the two instances below genuinely two replicas
    of one deployment rather than two objects in one process sharing a
    reference: neither holds the other's store, and the only thing between
    them is the key space.
    """
    import fakeredis
    import fakeredis.aioredis
    import redis.asyncio

    server = fakeredis.FakeServer()

    def _from_url(url: str, **kwargs: Any) -> Any:
        return fakeredis.aioredis.FakeRedis(server=server, **kwargs)

    monkeypatch.setattr(redis.asyncio, "from_url", _from_url)
    monkeypatch.setenv("POSTERN_REDIS_URL", "redis://fake.test:6379/0")
    yield server

```

with:

```python
    instance, and by the CLI running in its own thread and its own event loop
    -- reads ``POSTERN_REDIS_URL`` and ``POSTERN_REDIS_KEY_PREFIX`` and lands
    on this one key space. That is what makes the two instances below
    genuinely two replicas of one deployment rather than two objects in one
    process sharing a reference: neither holds the other's store, and the only
    thing between them is the key space.

    A `fakeredis` server until the layer-1 session token: a customer-client
    revocation is now one Lua script (``EVAL``), and fakeredis 2.38.0 without
    ``lupa`` answers "unknown command 'eval'".
    """
    monkeypatch.setenv("POSTERN_REDIS_URL", redis_url)
    monkeypatch.setenv("POSTERN_REDIS_KEY_PREFIX", f"zt7r{uuid4().hex[:12]}:")
    yield redis_url

```

- [ ] **Step 2: Run them to verify they fail**

Run: `uv run pytest tests/test_customer_revoked_at.py tests/test_device_grant.py tests/test_settings_bounds.py tests/test_zt7_confirm_revocation.py tests/test_zt7_revocation_reachable.py -q`

Expected: FAIL, `1 error`. The first failure reads `ImportError: cannot import name 'CUSTOMER_REVOKED_AT_TTL_SECONDS' from 'postern_core.auth.revocation'`.

- [ ] **Step 3: Implement**

In `packages/postern-core/src/postern_core/auth/revocation.py`, replace:

```python

FAIL CLOSED. A store that cannot answer raises `RevocationStoreUnavailable`
```

with:

```python

ONE KEY THAT DOES EXPIRE, AND IT IS NOT A REVOCATION. Every customer-plus-client
revocation also stamps WHEN it was written, per customer, in milliseconds:
``customer_revoked_at``. The layer-1 session token compares that instant with
when a refresh family was created and when a device code was approved, so a
family or an approval that predates a revocation stays refused after the
revocation is restored. The stamp outlives a restore on purpose and expires
after `CUSTOMER_REVOKED_AT_TTL_SECONDS`, the longest anything it could refuse
can live, because keeping a record that a named customer was cut off beyond
that serves nothing (GDPR Article 5(1)(e)).

FAIL CLOSED. A store that cannot answer raises `RevocationStoreUnavailable`
```

In `packages/postern-core/src/postern_core/auth/revocation.py`, replace:

```python
import os
from abc import ABC, abstractmethod
```

with:

```python
import os
import time
from abc import ABC, abstractmethod
```

In `packages/postern-core/src/postern_core/auth/revocation.py`, replace:

```python
logger = logging.getLogger(__name__)

```

with:

```python
logger = logging.getLogger(__name__)

#: How long ``customer_revoked_at`` remembers a customer revocation, restored
#: or not. The refresh-family lifetime (3,600 s) plus the default device-code
#: lifetime (900 s), the longest a family or an approved-but-unexchanged code
#: can outlive the revocation it must be compared with, plus 300 s for
#: replication lag and the 2-second cross-clock tolerance. A constant here and
#: not a setting, because the writer (`postern_core.auth.revoke_cli`, or an
#: operator's own backend) does not know confirm's settings; ``ConfirmSettings``
#: refuses a device-code lifetime that would outgrow it.
CUSTOMER_REVOKED_AT_TTL_SECONDS = 4_800

#: The revocation of a customer-client pair and its timestamp, as ONE
#: server-side step on ONE clock: ``TIME``, then the pair's ``SADD``, then the
#: customer's stamp with its expiry. Returns the stamp in milliseconds.
#:
#: A script that reads ``TIME`` and then writes must be replicated by its
#: effects rather than by its body. Effects replication is the default from
#: Redis 5.0 and the only mode from 7.0 (the Redis scripting introduction,
#: read 1 October 2026), so the operator's Redis must be 5.0 or later. The
#: two keys must share a slot, so it must not be a cluster. It runs as
#: written on the suite's ``redis:7-alpine``.
_REVOKE_CUSTOMER_CLIENT = (
    "local t = redis.call('TIME') "
    "local ms = tonumber(t[1]) * 1000 + math.floor(tonumber(t[2]) / 1000) "
    "redis.call('SADD', KEYS[1], ARGV[1]) "
    "redis.call('SET', KEYS[2], ms, 'EX', ARGV[2]) "
    "return ms"
)


def _now_ms() -> int:
    """This process's clock in milliseconds, for the in-memory backend."""
    return time.time_ns() // 1_000_000

```

In `packages/postern-core/src/postern_core/auth/revocation.py`, replace:

```python

    async def close(self) -> None:  # noqa: B027 - concrete and empty on purpose
```

with:

```python

    async def customer_revoked_at(self, customer_ref: str) -> int | None:
        """When a revocation last named this customer, in ms since the epoch, or ``None``.

        The latest instant any ``revoke_customer_client`` for this customer
        was written, KEPT AFTER ``restore_customer_client`` and for
        `CUSTOMER_REVOKED_AT_TTL_SECONDS` only. ``POST /token`` compares it
        with a device code's approval and with a refresh family's creation,
        so a grant that predates a revocation cannot be revived by a restore.

        CONCRETE AND ``None`` BY DEFAULT, as `is_customer_revoked` is
        concrete, so a test double that implements only the abstract methods
        keeps working. Raises `RevocationStoreUnavailable` when the store
        cannot answer.
        """
        return None

    async def close(self) -> None:  # noqa: B027 - concrete and empty on purpose
```

In `packages/postern-core/src/postern_core/auth/revocation.py`, replace:

```python
        self._clients: set[str] = set()

```

with:

```python
        self._clients: set[str] = set()
        #: ``customer_ref -> (stamp ms, expiry ms)``, swept on read.
        self._revoked_at: dict[str, tuple[int, int]] = {}

```

In `packages/postern-core/src/postern_core/auth/revocation.py`, replace:

```python
        self._customer_clients.add((customer_ref, client_id))

```

with:

```python
        self._customer_clients.add((customer_ref, client_id))
        stamp = _now_ms()
        self._revoked_at[customer_ref] = (stamp, stamp + CUSTOMER_REVOKED_AT_TTL_SECONDS * 1000)

    async def customer_revoked_at(self, customer_ref: str) -> int | None:
        entry = self._revoked_at.get(customer_ref)
        if entry is None:
            return None
        stamp, expires = entry
        if _now_ms() >= expires:
            del self._revoked_at[customer_ref]
            return None
        return stamp

```

In `packages/postern-core/src/postern_core/auth/revocation.py`, replace:

```python
        return f"{self._prefix}revoked:clients"

    async def is_revoked(self, claims: Mapping[str, Any]) -> bool:
        """Check every applicable scope in one round trip.
```

with:

```python
        return f"{self._prefix}revoked:clients"

    def _revoked_at_key(self, customer_ref: str) -> str:
        return f"{self._prefix}revoked:customer-at:{customer_ref}"

    async def is_revoked(self, claims: Mapping[str, Any]) -> bool:
        """Check every applicable scope in one round trip.
```

In `packages/postern-core/src/postern_core/auth/revocation.py`, replace:

```python
    async def revoke_customer_client(self, *, customer_ref: str, client_id: str) -> None:
        await self._add(self._pairs_key, _pair_member(customer_ref, client_id))

```

with:

```python
    async def revoke_customer_client(self, *, customer_ref: str, client_id: str) -> None:
        """The pair's ``SADD`` and the customer's stamp, in one script on Redis's clock."""
        try:
            await self._redis.eval(
                _REVOKE_CUSTOMER_CLIENT,
                2,
                self._pairs_key,
                self._revoked_at_key(customer_ref),
                _pair_member(customer_ref, client_id),
                CUSTOMER_REVOKED_AT_TTL_SECONDS,
            )
        except Exception as exc:
            raise RevocationStoreUnavailable(
                f"revocation entry could not be written: {type(exc).__name__}"
            ) from exc

    async def customer_revoked_at(self, customer_ref: str) -> int | None:
        try:
            raw = await self._redis.get(self._revoked_at_key(customer_ref))
        except Exception as exc:
            raise RevocationStoreUnavailable(
                f"revocation timestamp could not be read: {type(exc).__name__}"
            ) from exc
        return int(raw) if raw is not None else None

```

In `services/confirm/settings.py`, replace:

```python
)
from postern_core.auth.resource_uri import is_normal_https_resource
from postern_core.auth.vault import VaultSettings, vault_from_env
```

with:

```python
)
from postern_core.auth.refresh_sessions import SESSION_ABSOLUTE_LIFETIME
from postern_core.auth.resource_uri import is_normal_https_resource
from postern_core.auth.revocation import CUSTOMER_REVOKED_AT_TTL_SECONDS
from postern_core.auth.vault import VaultSettings, vault_from_env
```

In `services/confirm/settings.py`, replace:

```python
MIN_DEVICE_CODE_TTL_SECONDS = _MIN_DEVICE_CODE_TTL_SECONDS


def _device_code_ttl(name: str, default: int) -> int:
```

with:

```python
MIN_DEVICE_CODE_TTL_SECONDS = _MIN_DEVICE_CODE_TTL_SECONDS

#: The longest ``POSTERN_DEVICE_CODE_TTL_SECONDS`` the customer revocation
#: stamp can cover: `postern_core.auth.revocation`'s
#: ``CUSTOMER_REVOKED_AT_TTL_SECONDS`` less the refresh family's lifetime and
#: its 300-second margin, which is 900 today. An approved code must not
#: outlive the stamp it is compared with at ``POST /token``, and the stamp's
#: writer cannot read this service's settings, so the ceiling lands here.
MAX_DEVICE_CODE_TTL_SECONDS = (
    CUSTOMER_REVOKED_AT_TTL_SECONDS - int(SESSION_ABSOLUTE_LIFETIME.total_seconds()) - 300
)


def _device_code_ttl(name: str, default: int) -> int:
```

In `services/confirm/settings.py`, replace:

```python

    THE CEILING IS DELIBERATELY ABSENT. A lifetime that is too LONG is a
    real risk -- it widens the window in which a leaked ``device_code`` is
    worth relaying (A2) -- but it is a risk an operator can reason about and
    RFC 8628 sets no bound on. A value that is too SHORT is different in
    kind: it does not weaken a control, it produces a service that cannot
    complete a pairing at all, and on the Redis backend it does so silently.
    Only the second one is unrepresentable, so only the second one is
    refused here.

```

with:

```python

    A CEILING SINCE THE LAYER-1 SESSION TOKEN, `MAX_DEVICE_CODE_TTL_SECONDS`.
    Until then a lifetime that was too LONG was left to the operator, as a
    risk RFC 8628 sets no bound on. It is now unrepresentable in a narrower
    sense: an approved code longer-lived than the customer revocation stamp
    could be redeemed after a revoke-and-restore that the stamp no longer
    remembers. A value that is too SHORT is refused for the older reason: it
    produces a service that cannot complete a pairing at all, and on the
    Redis backend it does so silently.

```

In `services/confirm/settings.py`, replace:

```python
            "the Redis store's truncation discards the code without storing it at all."
        )
```

with:

```python
            "the Redis store's truncation discards the code without storing it at all."
        )
    if value > MAX_DEVICE_CODE_TTL_SECONDS:
        raise ValueError(
            f"{name} must be at most {MAX_DEVICE_CODE_TTL_SECONDS} seconds, got {value}. "
            "An approved device code must not outlive the customer revocation stamp "
            f"({CUSTOMER_REVOKED_AT_TTL_SECONDS} seconds) that POST /token compares its "
            "approval with, less the one-hour session family and a 300-second margin."
        )
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `uv run pytest tests/test_customer_revoked_at.py tests/test_device_grant.py tests/test_settings_bounds.py tests/test_zt7_confirm_revocation.py tests/test_zt7_revocation_reachable.py -q`

Expected: 543 passed

- [ ] **Step 5: Format, then run the gate**

Run: `uv run ruff format packages services tests && make ci`

Expected: exit 0 (3644 passed at validation).

- [ ] **Step 6: Commit**

```bash
git add packages/postern-core/src/postern_core/auth/revocation.py services/confirm/settings.py tests/test_customer_revoked_at.py tests/test_device_grant.py tests/test_settings_bounds.py tests/test_zt7_confirm_revocation.py tests/test_zt7_revocation_reachable.py
git commit -m "feat(core): stamp when a customer was last revoked, in milliseconds" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 5: Startup refusals: shared state, and the session issuer and audience

Spec section 4's "Shared state is required, and enforced" and section 2's refusals, wired into `create_confirm_app` beside `enforce_redis_requirement` and after it. The dataclass defaults are the safe values, so every test that builds `ConfirmSettings(...)` by hand and assembles an app now passes the two development flags `ConfirmSettings.for_testing` sets, as the spec's Compatibility section says it must.

**Files:**
- Modify: `services/confirm/main.py` (`_refuse_process_local_sessions`, `create_confirm_app`)
- Modify: `tests/test_approval_concurrency.py`
- Modify: `tests/test_approval_integration.py`
- Modify: `tests/test_audit_reserve.py`
- Modify: `tests/test_confirm_auth.py`
- Modify: `tests/test_confirm_body_limit.py`
- Modify: `tests/test_device_signature.py`
- Modify: `tests/test_ephemeral_key_warning.py`
- Modify: `tests/test_pool_sizing.py`
- Modify: `tests/test_require_redis_guard.py`
- Create: `tests/test_session_startup_refusals.py`
- Modify: `tests/test_write_audit.py`
- Modify: `tests/test_write_audit_arguments_cap.py`
- Modify: `tests/test_zt7_confirm_revocation.py`

- [ ] **Step 1: Write the failing tests**

The churn is mechanical: each hand-built `ConfirmSettings(...)` that reaches `create_confirm_app` gains `allow_non_uri_audience=True, allow_process_local_sessions=True`, with the same two-line comment.

In `tests/test_approval_concurrency.py`, replace:

```python
        database_url=pg_url,
    )
```

with:

```python
        database_url=pg_url,
        # The two development flags `ConfirmSettings.for_testing` sets: this
        # settings object is built by hand, so it gets the safe defaults.
        allow_non_uri_audience=True,
        allow_process_local_sessions=True,
    )
```

In `tests/test_approval_integration.py`, replace:

```python
        database_url=pg_url,
    )
```

with:

```python
        database_url=pg_url,
        # The two development flags `ConfirmSettings.for_testing` sets: this
        # settings object is built by hand, so it gets the safe defaults.
        allow_non_uri_audience=True,
        allow_process_local_sessions=True,
    )
```

In `tests/test_audit_reserve.py`, replace:

```python
        "database_pool_size": 1,
        "database_max_overflow": 0,
        "database_pool_timeout_seconds": POOL_TIMEOUT,
    }
    fields.update(overrides)
    return ConfirmSettings(**fields)
```

with:

```python
        "database_pool_size": 1,
        "database_max_overflow": 0,
        "database_pool_timeout_seconds": POOL_TIMEOUT,
        # The two development flags `ConfirmSettings.for_testing` sets: this
        # settings object is built by hand, so it gets the safe defaults.
        "allow_non_uri_audience": True,
        "allow_process_local_sessions": True,
    }
    fields.update(overrides)
    return ConfirmSettings(**fields)
```

In `tests/test_confirm_auth.py`, replace:

```python
        app_assertion_audience=v["app_assertion_audience"],
    )
```

with:

```python
        app_assertion_audience=v["app_assertion_audience"],
        # The two development flags `ConfirmSettings.for_testing` sets: this
        # settings object is built by hand, so it gets the safe defaults.
        allow_non_uri_audience=True,
        allow_process_local_sessions=True,
    )
```

In `tests/test_confirm_body_limit.py`, replace:

```python
        app_assertion_audience=AUDIENCE,
        **kwargs,
```

with:

```python
        app_assertion_audience=AUDIENCE,
        # The two development flags `ConfirmSettings.for_testing` sets: this
        # settings object is built by hand, so it gets the safe defaults.
        allow_non_uri_audience=True,
        allow_process_local_sessions=True,
        **kwargs,
```

In `tests/test_confirm_body_limit.py`, replace:

```python
        app_assertion_audience=AUDIENCE,
        max_body_bytes=LIMIT,
    )
    app = create_confirm_app(
```

with:

```python
        app_assertion_audience=AUDIENCE,
        max_body_bytes=LIMIT,
        # The two development flags `ConfirmSettings.for_testing` sets: this
        # settings object is built by hand, so it gets the safe defaults.
        allow_non_uri_audience=True,
        allow_process_local_sessions=True,
    )
    app = create_confirm_app(
```

In `tests/test_confirm_body_limit.py`, replace:

```python
def settings(pg_url: str) -> ConfirmSettings:
    return ConfirmSettings(backend_base_url="https://backend.test", database_url=pg_url)

```

with:

```python
def settings(pg_url: str) -> ConfirmSettings:
    return ConfirmSettings(
        backend_base_url="https://backend.test",
        database_url=pg_url,
        # The two development flags `ConfirmSettings.for_testing` sets: this
        # settings object is built by hand, so it gets the safe defaults.
        allow_non_uri_audience=True,
        allow_process_local_sessions=True,
    )

```

In `tests/test_confirm_body_limit.py`, replace:

```python
        max_body_bytes=LIMIT,
    )
```

with:

```python
        max_body_bytes=LIMIT,
        # The two development flags `ConfirmSettings.for_testing` sets: this
        # settings object is built by hand, so it gets the safe defaults.
        allow_non_uri_audience=True,
        allow_process_local_sessions=True,
    )
```

In `tests/test_device_signature.py`, replace:

```python
def settings(pg_url: str) -> ConfirmSettings:
    return ConfirmSettings(backend_base_url="https://backend.test", database_url=pg_url)

```

with:

```python
def settings(pg_url: str) -> ConfirmSettings:
    return ConfirmSettings(
        backend_base_url="https://backend.test",
        database_url=pg_url,
        # The two development flags `ConfirmSettings.for_testing` sets: this
        # settings object is built by hand, so it gets the safe defaults.
        allow_non_uri_audience=True,
        allow_process_local_sessions=True,
    )

```

In `tests/test_device_signature.py`, replace:

```python
        device_keys_path=str(document),
    )
```

with:

```python
        device_keys_path=str(document),
        # The two development flags `ConfirmSettings.for_testing` sets: this
        # settings object is built by hand, so it gets the safe defaults.
        allow_non_uri_audience=True,
        allow_process_local_sessions=True,
    )
```

In `tests/test_ephemeral_key_warning.py`, replace:

```python
        app_assertion_audience="postern-confirm",
    )
```

with:

```python
        app_assertion_audience="postern-confirm",
        # The two development flags `ConfirmSettings.for_testing` sets: this
        # settings object is built by hand, so it gets the safe defaults.
        allow_non_uri_audience=True,
        allow_process_local_sessions=True,
    )
```

In `tests/test_pool_sizing.py`, replace:

```python
        database_pool_timeout_seconds=pool_timeout_seconds,
    )
```

with:

```python
        database_pool_timeout_seconds=pool_timeout_seconds,
        # The two development flags `ConfirmSettings.for_testing` sets: this
        # settings object is built by hand, so it gets the safe defaults.
        allow_non_uri_audience=True,
        allow_process_local_sessions=True,
    )
```

In `tests/test_require_redis_guard.py`, replace:

```python
        assert "inbound authentication" in str(raised.value)

```

with:

```python
        assert "inbound authentication" in str(raised.value)


class TestTheSessionRefusalComesAfterTheRedisGuard:
    """``_refuse_process_local_sessions`` sits beside this guard and after it.

    The device grant's own refusal of per-process state is narrower -- it is
    about refresh families and recalls, and it has a development flag -- so
    an operator who also set POSTERN_REQUIRE_REDIS hears the deployment-wide
    contract's message first.
    """

    def test_required_and_absent_hears_this_guard_first(
        self, key_pair: RSAKeyPair, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(REQUIRE_REDIS_ENV, "1")
        with pytest.raises(RuntimeError) as raised:
            _confirm(key_pair, allow_process_local_sessions=False)
        assert str(raised.value).startswith(SHARED_PREFIX)

    def test_not_required_and_absent_hears_the_session_refusal(self, key_pair: RSAKeyPair) -> None:
        with pytest.raises(RuntimeError) as raised:
            _confirm(key_pair, allow_process_local_sessions=False)
        assert not str(raised.value).startswith(SHARED_PREFIX)
        assert "POSTERN_ALLOW_PROCESS_LOCAL_SESSIONS" in str(raised.value)

```

Create `tests/test_session_startup_refusals.py` with:

```python
"""``create_confirm_app`` refuses a device grant it could not run safely.

Spec sections 2 and 4 of ``dev-docs/device-grant-session-token-spec.md``: no
shared Redis and no development flag refuses to start; the flag starts and
warns; and the issuer and audience refusals of
``check_session_token_settings`` fire at startup, where a deployment would
meet them, for a settings object built by hand as much as for one read from
the environment.
"""

from __future__ import annotations

import dataclasses
import logging
from typing import Any

import pytest
from fastmcp.server.auth.providers.jwt import JWTVerifier, RSAKeyPair
from postern_core.auth.device_keys import no_enrolled_devices

from services.confirm.main import create_confirm_app
from services.confirm.settings import ConfirmSettings
from tests.test_device_grant import AUDIENCE, ISSUER


@pytest.fixture(scope="module")
def key_pair() -> RSAKeyPair:
    return RSAKeyPair.generate()


@pytest.fixture(autouse=True)
def _no_redis(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("POSTERN_REDIS_URL", raising=False)
    monkeypatch.delenv("POSTERN_REQUIRE_REDIS", raising=False)


def _confirm(key_pair: RSAKeyPair, **overrides: Any) -> Any:
    return create_confirm_app(
        dataclasses.replace(ConfirmSettings.for_testing(), **overrides),
        assertion_verifier=JWTVerifier(
            public_key=key_pair.public_key, issuer=ISSUER, audience=AUDIENCE
        ),
        device_key_store=no_enrolled_devices(),
    )


class TestSharedStateIsRequired:
    def test_no_redis_and_no_flag_refuses_naming_both_ways_out(self, key_pair: RSAKeyPair) -> None:
        with pytest.raises(RuntimeError) as raised:
            _confirm(key_pair, allow_process_local_sessions=False)
        message = str(raised.value)
        assert "POSTERN_REDIS_URL" in message
        assert "POSTERN_ALLOW_PROCESS_LOCAL_SESSIONS" in message

    def test_an_empty_url_counts_as_absent(
        self, key_pair: RSAKeyPair, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("POSTERN_REDIS_URL", "")
        with pytest.raises(RuntimeError):
            _confirm(key_pair, allow_process_local_sessions=False)

    def test_the_flag_starts_and_warns(
        self, key_pair: RSAKeyPair, caplog: pytest.LogCaptureFixture
    ) -> None:
        with caplog.at_level(logging.WARNING, logger="services.confirm.main"):
            assert _confirm(key_pair, allow_process_local_sessions=True) is not None
        assert "POSTERN_ALLOW_PROCESS_LOCAL_SESSIONS is set" in caplog.text

    def test_a_redis_url_starts_without_the_flag_and_without_the_warning(
        self,
        key_pair: RSAKeyPair,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        monkeypatch.setenv("POSTERN_REDIS_URL", "redis://127.0.0.1:6379/0")
        with caplog.at_level(logging.WARNING, logger="services.confirm.main"):
            assert _confirm(key_pair, allow_process_local_sessions=False) is not None
        assert "POSTERN_ALLOW_PROCESS_LOCAL_SESSIONS" not in caplog.text


class TestTheSessionSettingsAreCheckedAtStartup:
    def test_a_non_uri_audience_without_the_flag_refuses(self, key_pair: RSAKeyPair) -> None:
        with pytest.raises(ValueError, match="POSTERN_SESSION_TOKEN_AUDIENCE"):
            _confirm(key_pair, allow_non_uri_audience=False)

    def test_a_uri_audience_starts_without_the_flag(self, key_pair: RSAKeyPair) -> None:
        app = _confirm(
            key_pair,
            allow_non_uri_audience=False,
            session_token_audience="https://mcp.postern.internal/mcp",  # noqa: S106
        )
        assert app is not None

    def test_an_issuer_shared_with_the_write_token_refuses(self, key_pair: RSAKeyPair) -> None:
        with pytest.raises(ValueError, match="POSTERN_WRITE_TOKEN_ISSUER"):
            _confirm(key_pair, session_token_issuer="https://mcp-write.internal")  # noqa: S106

    def test_a_hand_built_settings_object_is_refused_twice_over(self, key_pair: RSAKeyPair) -> None:
        """The dataclass defaults are the safe values: no Redis URL and a
        non-URI audience both refuse, and the Redis refusal is heard first."""
        settings = ConfirmSettings(
            app_assertion_jwks_uri="https://app.test.invalid/.well-known/jwks.json",
            app_assertion_issuer=ISSUER,
            app_assertion_audience=AUDIENCE,
        )
        with pytest.raises(RuntimeError, match="POSTERN_ALLOW_PROCESS_LOCAL_SESSIONS"):
            create_confirm_app(
                settings,
                assertion_verifier=JWTVerifier(
                    public_key=key_pair.public_key, issuer=ISSUER, audience=AUDIENCE
                ),
                device_key_store=no_enrolled_devices(),
            )
        with pytest.raises(ValueError, match="POSTERN_SESSION_TOKEN_AUDIENCE"):
            create_confirm_app(
                dataclasses.replace(settings, allow_process_local_sessions=True),
                assertion_verifier=JWTVerifier(
                    public_key=key_pair.public_key, issuer=ISSUER, audience=AUDIENCE
                ),
                device_key_store=no_enrolled_devices(),
            )
```

In `tests/test_write_audit.py`, replace:

```python
def settings(pg_url: str) -> ConfirmSettings:
    return ConfirmSettings(backend_base_url="https://backend.test", database_url=pg_url)

```

with:

```python
def settings(pg_url: str) -> ConfirmSettings:
    return ConfirmSettings(
        backend_base_url="https://backend.test",
        database_url=pg_url,
        # The two development flags `ConfirmSettings.for_testing` sets: this
        # settings object is built by hand, so it gets the safe defaults.
        allow_non_uri_audience=True,
        allow_process_local_sessions=True,
    )

```

In `tests/test_write_audit_arguments_cap.py`, replace:

```python
        max_body_bytes=2 * len(ONE_MIB),
    )
```

with:

```python
        max_body_bytes=2 * len(ONE_MIB),
        # The two development flags `ConfirmSettings.for_testing` sets: this
        # settings object is built by hand, so it gets the safe defaults.
        allow_non_uri_audience=True,
        allow_process_local_sessions=True,
    )
```

In `tests/test_zt7_confirm_revocation.py`, replace:

```python
def settings(pg_url: str) -> ConfirmSettings:
    return ConfirmSettings(backend_base_url="https://backend.test", database_url=pg_url)

```

with:

```python
def settings(pg_url: str) -> ConfirmSettings:
    return ConfirmSettings(
        backend_base_url="https://backend.test",
        database_url=pg_url,
        # The two development flags `ConfirmSettings.for_testing` sets: this
        # settings object is built by hand, so it gets the safe defaults.
        allow_non_uri_audience=True,
        allow_process_local_sessions=True,
    )

```

- [ ] **Step 2: Run them to verify they fail**

Run: `uv run pytest tests/test_approval_concurrency.py tests/test_approval_integration.py tests/test_audit_reserve.py tests/test_confirm_auth.py tests/test_confirm_body_limit.py tests/test_device_signature.py tests/test_ephemeral_key_warning.py tests/test_pool_sizing.py tests/test_require_redis_guard.py tests/test_session_startup_refusals.py tests/test_write_audit.py tests/test_write_audit_arguments_cap.py tests/test_zt7_confirm_revocation.py -q`

Expected: FAIL, `7 failed, 313 passed`. The first failure reads `Failed: DID NOT RAISE RuntimeError`.

- [ ] **Step 3: Implement**

In `services/confirm/main.py`, replace:

```python
import enum
from pathlib import Path
```

with:

```python
import enum
import logging
import os
from pathlib import Path
```

In `services/confirm/main.py`, replace:

```python
from services.confirm.session_token import build_session_minter
from services.confirm.settings import ConfirmSettings
from services.confirm.verify_page import verify_page_routes

```

with:

```python
from services.confirm.session_token import build_session_minter
from services.confirm.settings import ConfirmSettings, check_session_token_settings
from services.confirm.verify_page import verify_page_routes

logger = logging.getLogger(__name__)

```

In `services/confirm/main.py`, replace:

```python

def create_confirm_app(
```

with:

```python

def _refuse_process_local_sessions(settings: ConfirmSettings) -> None:
    """Refuse to start the device grant on per-process state, unless told to.

    Without ``POSTERN_REDIS_URL`` the refresh-family store and this service's
    ZT-7 store are per process: a refresh token from one replica is
    ``invalid_grant`` at another, and a recall at ``POST /scan`` writes the
    revoked ``jti`` into this process's memory, which ``services/api`` never
    reads. A service that cannot recall should not look ready, so this is a
    refusal at startup and not at ``POST /token``.

    ``POSTERN_ALLOW_PROCESS_LOCAL_SESSIONS`` is the development way out; with
    it the service starts, says so here, and every recall row records
    ``recall_local_only``. ``RuntimeError``, the type
    `postern_core.config.enforce_redis_requirement` chose for a
    deployment-wide contract not met.
    """
    if os.environ.get("POSTERN_REDIS_URL"):
        return
    if settings.allow_process_local_sessions:
        logger.warning(
            "POSTERN_ALLOW_PROCESS_LOCAL_SESSIONS is set and POSTERN_REDIS_URL is not: "
            "refresh families and recalls live in this process only, and services/api "
            "never sees a recalled token. No multi-replica deployment may run this way."
        )
        return
    raise RuntimeError(
        "the confirm service cannot issue layer-1 sessions without shared state: "
        "POSTERN_REDIS_URL is not set, so refresh families and the ZT-7 list would be "
        "per process, a refresh token from one replica would be refused at another, and a "
        "recall at POST /scan would never reach services/api. Set POSTERN_REDIS_URL to "
        "the Redis services/api uses, or set POSTERN_ALLOW_PROCESS_LOCAL_SESSIONS for a "
        "single-process development stack."
    )


def create_confirm_app(
```

In `services/confirm/main.py`, replace:

```python
            verify an approval signature, unreachable by construction rather
            than by remembering to configure one.
        EnricherSeamViolation: if the installed enricher set is refused by
```

with:

```python
            verify an approval signature, unreachable by construction rather
            than by remembering to configure one. Also for every refusal
            ``check_session_token_settings`` makes.
        RuntimeError: if ``POSTERN_REDIS_URL`` is unset and
            ``allow_process_local_sessions`` is not (see
            ``_refuse_process_local_sessions``), after
            ``enforce_redis_requirement``'s own refusal.
        EnricherSeamViolation: if the installed enricher set is refused by
```

In `services/confirm/main.py`, replace:

```python
        )
    )

    # THE PAIRING NETWORK ENRICHER, LOADED ONCE AND BEFORE ANY KEY IS BUILT,
```

with:

```python
        )
    )
    # BESIDE THAT GUARD AND AFTER IT, so an operator who also set
    # POSTERN_REQUIRE_REDIS hears its message first. This one is the device
    # grant's own: without a shared Redis a session cannot be refreshed on
    # another replica or recalled at all.
    _refuse_process_local_sessions(settings)
    # The issuer and audience of every access token, refused here rather than
    # in `ConfirmSettings.__post_init__` so a settings object built by hand is
    # refused exactly where a deployment would be.
    check_session_token_settings(settings)

    # THE PAIRING NETWORK ENRICHER, LOADED ONCE AND BEFORE ANY KEY IS BUILT,
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `uv run pytest tests/test_approval_concurrency.py tests/test_approval_integration.py tests/test_audit_reserve.py tests/test_confirm_auth.py tests/test_confirm_body_limit.py tests/test_device_signature.py tests/test_ephemeral_key_warning.py tests/test_pool_sizing.py tests/test_require_redis_guard.py tests/test_session_startup_refusals.py tests/test_write_audit.py tests/test_write_audit_arguments_cap.py tests/test_zt7_confirm_revocation.py -q`

Expected: 320 passed

- [ ] **Step 5: Format, then run the gate**

Run: `uv run ruff format packages services tests && make ci`

Expected: exit 0 (3654 passed at validation).

- [ ] **Step 6: Commit**

```bash
git add services/confirm/main.py tests/test_approval_concurrency.py tests/test_approval_integration.py tests/test_audit_reserve.py tests/test_confirm_auth.py tests/test_confirm_body_limit.py tests/test_device_signature.py tests/test_ephemeral_key_warning.py tests/test_pool_sizing.py tests/test_require_redis_guard.py tests/test_session_startup_refusals.py tests/test_write_audit.py tests/test_write_audit_arguments_cap.py tests/test_zt7_confirm_revocation.py
git commit -m "feat(confirm): refuse a device grant without shared state or a URI audience" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 6: `POST /token` issues a layer-1 session

Spec section 5 in full, and section 9's `names(session_id=)`: the hotfix's 503 path is replaced by steps 0 to 5 (revoked since approval, draw, create the family, spend the code with `session_id`, sign, row). `token_endpoint` becomes a wrapper that stamps `Cache-Control: no-store` and `Pragma: no-cache` on every answer; `resource` is checked before the lookup; both retryable 503s carry `Retry-After`; `/device_authorization` refuses `client_id` `-`. The hotfix's own assertions invert (spec, Compatibility), `consume_device_code` gains its required `session_id` in every test that calls it, and the end-to-end regression narrows to "no layer-2 token, every JWT a session token". One sentence of the spec is rewritten so the citation gate stays green (Verified facts).

**Files:**
- Modify: `dev-docs/device-grant-session-token-spec.md` (one sentence of the Compatibility section)
- Modify: `packages/postern-core/src/postern_core/auth/device_codes.py` (`DeviceCode.session_id`, `consume_device_code` on the base and both backends, the two dict helpers)
- Modify: `services/confirm/audit.py` (`PairingAudit.names`, `__slots__`, `_arguments`, `minted`; `DETAIL_ISSUANCE_DISABLED`'s comment)
- Modify: `services/confirm/device_auth.py` (`RESERVED_CLIENT_ID`, `TOKEN_RESPONSE_HEADERS`, `APPROVAL_CLOCK_TOLERANCE_MS`, `token_endpoint`, `_resource_refusal`, `_token_response`, `_exchange`, `_session_store_full_response`, `device_auth_routes` (no longer takes `read_minter`, and takes no session parameters))
- Modify: `services/confirm/main.py` (the family store, `device_auth_routes` call, `app.state.refresh_session_store`)
- Modify: `services/confirm/revocation.py` (`customer_revoked_since`, `store_unavailable_response`)
- Modify: `tests/device_grant_helpers.py`
- Modify: `tests/test_confirm_rate_limit.py`
- Modify: `tests/test_device_code_pairing_store.py`
- Modify: `tests/test_device_code_scanner_ip.py`
- Modify: `tests/test_device_grant.py`
- Modify: `tests/test_pairing_audit.py`
- Modify: `tests/test_qr_pairing_end_to_end.py`
- Modify: `tests/test_redis_backed_stores.py`
- Modify: `tests/test_scan.py`
- Modify: `tests/test_scan_network_signal.py`
- Create: `tests/test_token_session_issuance.py`
- Modify: `tests/test_zt7_confirm_revocation.py`

- [ ] **Step 1: Write the failing tests**

The ``ISSUANCE_DISABLED_BODY`` constant in `tests/device_grant_helpers.py` is replaced by ``session_claims``, which asserts the five keys, both headers and a token that verifies against `/session/jwks.json`, and returns the claims. Every `consume_device_code(x)` in the tests becomes `consume_device_code(x, session_id="")`.

In `tests/device_grant_helpers.py`, replace:

```python
from services.confirm.qr_token import slot_at, token_for

```

with:

```python
from services.confirm.qr_token import slot_at, token_for
from services.confirm.session_token import ACCESS_TOKEN_LIFETIME_SECONDS

```

In `tests/device_grant_helpers.py`, replace:

```python

#: What ``POST /token`` answers for an approved, unexpired device code since
#: 2026-09-30, byte for byte. Issuance is disabled until the layer-1 session
#: token lands: the token this endpoint used to return was a layer-2 backend
#: token (``aud=accounts.svc``, signed with the read key ``services/api``
#: publishes), which a public client must never hold.
ISSUANCE_DISABLED_BODY = {
    "error": "temporarily_unavailable",
    "error_description": "session token issuance is not enabled",
}

```

with:

```python

#: The five keys of ``POST /token``'s success body, spec section 5, and no
#: other: in particular nothing a layer-2 verifier would accept.
SESSION_RESPONSE_KEYS = frozenset(
    {"access_token", "token_type", "expires_in", "refresh_token", "scope"}
)


def session_claims(response: Any, app: Starlette) -> dict[str, Any]:
    """Assert ``response`` is a session issued by ``app``; return the access token's claims.

    The exact key set, both RFC 6749 section 5.1 headers, and an access token
    that verifies against the key set ``/session/jwks.json`` publishes, under
    the configured issuer and audience, with no ``act``. The refresh token
    names the same family the access token's ``sid`` does.
    """
    assert response.status_code == 200, response.text
    body = response.json()
    assert set(body) == SESSION_RESPONSE_KEYS, body
    assert body["token_type"] == "Bearer"  # noqa: S105
    assert body["expires_in"] == ACCESS_TOKEN_LIFETIME_SECONDS
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["pragma"] == "no-cache"
    published = app.state.postern_session_key_source.public_jwks()
    claims = dict(
        joserfc_jwt.decode(
            body["access_token"],
            KeySet.import_key_set(published),
            algorithms=["RS256"],
        ).claims
    )
    settings = app.state.settings
    assert claims["iss"] == settings.session_token_issuer
    assert claims["aud"] == settings.session_token_audience
    assert "act" not in claims
    assert claims["scope"] == body["scope"]
    assert body["refresh_token"].split(".")[1] == claims["sid"]
    return claims


```

In `tests/device_grant_helpers.py`, replace:

```python
def assert_no_body_carries_a_token_the_api_trusts(
    bodies: list[str], api_jwks: dict[str, Any]
) -> None:
```

with:

```python
def assert_no_body_carries_a_token_the_api_trusts(
    bodies: list[str],
    api_jwks: dict[str, Any],
    session_jwks: dict[str, Any],
    *,
    issuer: str,
    audience: str,
) -> None:
```

In `tests/device_grant_helpers.py`, replace:

```python
    string in any body verifies against the JWKS ``services/api`` publishes,
    which is the key set Istio trusts; and no body holds anything JWT-shaped
    at all.
    """
```

with:

```python
    string in any body verifies against the JWKS ``services/api`` publishes,
    which is the key set Istio trusts; and every JWT-shaped string in any body
    is a layer-1 session token -- it verifies against ``/session/jwks.json``
    and carries the session issuer and audience.
    """
```

In `tests/device_grant_helpers.py`, replace:

```python
    assert trusted == [], "a /token response carried a token the api's JWKS verifies"
    assert shaped == [], f"a /token response carried a JWT-shaped string: {shaped!r}"
```

with:

```python
    assert trusted == [], "a /token response carried a token the api's JWKS verifies"
    session_keys = KeySet.import_key_set(session_jwks)  # type: ignore[arg-type]
    for token in shaped:
        claims = joserfc_jwt.decode(token, session_keys, algorithms=["RS256"]).claims
        assert claims["iss"] == issuer, claims
        assert claims["aud"] == audience, claims
```

> **Amended 1 October 2026 (review follow-up, commit after Task 6).** The tree differs from the helper blocks above. ``session_claims`` also asserts that no key confirm publishes at ``/.well-known/jwks.json`` signed the access token. A new ``signed_by_any_key_in`` tries each key on its own, ignoring the ``kid``, and the e2e helper uses it for the api's read JWKS and for an optional ``write_jwks`` keyword argument.

In `tests/test_confirm_rate_limit.py`, replace:

```python
from services.confirm.settings import ConfirmSettings
from tests.device_grant_helpers import ISSUANCE_DISABLED_BODY, scan_in_store
from tests.test_device_grant import AUDIENCE, ISSUER, bearer
```

with:

```python
from services.confirm.settings import ConfirmSettings
from tests.device_grant_helpers import scan_in_store, session_claims
from tests.test_device_grant import AUDIENCE, ISSUER, bearer
```

In `tests/test_confirm_rate_limit.py`, replace:

```python
        Three requests, nowhere near any limit. The poll reaches the handler
        and gets the issuance-disabled 503 (no token since 2026-09-30), which
        is not the limiter's 429.
        """
```

with:

```python
        Three requests, nowhere near any limit. The poll reaches the handler
        and is issued a session, which is not the limiter's 429.
        """
```

In `tests/test_confirm_rate_limit.py`, replace:

```python

        assert exchanged.status_code == 503
        assert exchanged.json() == ISSUANCE_DISABLED_BODY
        assert "write_token" not in exchanged.json()
```

with:

```python

        session_claims(exchanged, app)
        assert "write_token" not in exchanged.json()
```

In `tests/test_confirm_rate_limit.py`, replace:

```python
            )
        # Reached the handler, not the flooded bucket's 429: the issuance-
        # disabled 503 every approved code gets since 2026-09-30.
        assert exchanged.status_code == 503
        assert exchanged.json() == ISSUANCE_DISABLED_BODY

```

with:

```python
            )
        # Reached the handler, not the flooded bucket's 429: a session.
        session_claims(exchanged, app)

```

In `tests/test_confirm_rate_limit.py`, replace:

```python

        SINCE 2026-09-30 NO EXCHANGE SPENDS A CODE, because issuance is
        disabled pending the layer-1 session token, so the first poll here gets
        the issuance-disabled 503 and leaves the code unspent. The code is then
        spent through the store, the state a build before 2026-09-30 left
        behind and the session-token change will produce again, and the other
        19 polls meet the spent-code refusal.

```

with:

```python

        The first poll is issued a session and spends the code, and the
        other 19 meet the spent-code refusal.

```

In `tests/test_confirm_rate_limit.py`, replace:

```python
            body = {"grant_type": "device_code", "device_code": device["device_code"]}
            answers = [await client.post("/token", data=body)]
            assert await app.state.device_code_store.consume_device_code(device["device_code"]), (
                "the refused first poll had already spent the code"
            )
            answers += [await client.post("/token", data=body) for _ in range(19)]

        statuses = [r.status_code for r in answers]
        assert statuses == [503] + [400] * 19
        assert answers[0].json() == ISSUANCE_DISABLED_BODY
        errors = [r.json()["error"] for r in answers[1:]]
```

with:

```python
            body = {"grant_type": "device_code", "device_code": device["device_code"]}
            answers = [await client.post("/token", data=body) for _ in range(20)]

        statuses = [r.status_code for r in answers]
        assert statuses == [200] + [400] * 19
        session_claims(answers[0], app)
        errors = [r.json()["error"] for r in answers[1:]]
```

In `tests/test_device_code_pairing_store.py`, replace:

```python

        assert await store.consume_device_code(code.device_code) is True

```

with:

```python

        assert await store.consume_device_code(code.device_code, session_id="") is True

```

In `tests/test_device_code_pairing_store.py`, replace:

```python
        await store.approve_scanned(code.device_code, BOB)
        await store.consume_device_code(code.device_code)
        before = await store.get_device_code(code.device_code)
```

with:

```python
        await store.approve_scanned(code.device_code, BOB)
        await store.consume_device_code(code.device_code, session_id="")
        before = await store.get_device_code(code.device_code)
```

In `tests/test_device_code_scanner_ip.py`, replace:

```python
    await writer.approve_scanned(code.device_code, BOB)
    await writer.consume_device_code(code.device_code)
    before = await _read(reader, code.device_code)
```

with:

```python
    await writer.approve_scanned(code.device_code, BOB)
    await writer.consume_device_code(code.device_code, session_id="")
    before = await _read(reader, code.device_code)
```

In `tests/test_device_grant.py`, replace:

```python
  expired, slow_down) — public, no bearer, and never returns a write token
  (audit finding C-01). Since 2026-09-30 it returns no token at all: an
  approved code gets a 503 because issuance is disabled pending the layer-1
  session token, and the code is not spent.
- Mobile app approval callback (``POST /approve``) — requires a verified
```

with:

```python
  expired, slow_down) — public, no bearer, and never returns a write token
  (audit finding C-01). An approved code is issued a layer-1 session and
  spent; ``tests/test_token_session_issuance.py`` holds the session's own
  properties.
- Mobile app approval callback (``POST /approve``) — requires a verified
```

In `tests/test_device_grant.py`, replace:

```python
from tests.device_grant_helpers import (
    ISSUANCE_DISABLED_BODY,
    jwt_shaped_strings,
    scan_in_store,
)
```

with:

```python
from tests.device_grant_helpers import (
    jwt_shaped_strings,
    scan_in_store,
    session_claims,
)
```

In `tests/test_device_grant.py`, replace:

```python

    async def test_approved_exchange_is_refused_and_the_approval_names_the_bearer_subject(
        self, app: Starlette, key_pair: RSAKeyPair
```

with:

```python

    async def test_approved_exchange_issues_a_session_for_the_bearer_subject(
        self, app: Starlette, key_pair: RSAKeyPair
```

In `tests/test_device_grant.py`, replace:

```python
        `/device_authorization` controls; it now reads `customer_ref`, which
        only a verified `/approve` write ever sets (audit finding C-01).

        Since 2026-09-30 an approved code gets the issuance-disabled 503 and
        no token, so the identity is asserted on the stored code instead of
        on a minted token's `sub`."""
        async with _client(app) as client:
```

with:

```python
        `/device_authorization` controls; it now reads `customer_ref`, which
        only a verified `/approve` write ever sets (audit finding C-01). The
        session's `sub` is that customer, and the browser's `client_id` is
        carried as a claim marked unverified, never as the subject."""
        async with _client(app) as client:
```

In `tests/test_device_grant.py`, replace:

```python

        assert resp.status_code == 503
        assert resp.json() == ISSUANCE_DISABLED_BODY
        assert jwt_shaped_strings(resp.text) == []

```

with:

```python

        claims = session_claims(resp, app)
        assert claims["sub"] == "cust_7f3a"
        assert claims["client_id"] == "cust_should_be_ignored"
        assert claims["client_id_verified"] is False

```

In `tests/test_device_grant.py`, replace:

```python
        assert stored.customer_ref == "cust_7f3a"
        assert stored.exchanged_at is None

```

with:

```python
        assert stored.customer_ref == "cust_7f3a"
        assert stored.exchanged_at is not None
        assert stored.session_id == claims["sid"]

```

In `tests/test_device_grant.py`, replace:

```python

            # Step 4: Poll token after approval → the issuance-disabled 503,
            # and no token of any kind in the body.
            resp = await client.post(
```

with:

```python

            # Step 4: Poll token after approval → a layer-1 session.
            resp = await client.post(
```

In `tests/test_device_grant.py`, replace:

```python
            )
            assert resp.status_code == 503
            assert resp.json() == ISSUANCE_DISABLED_BODY
            assert jwt_shaped_strings(resp.text) == []

```

with:

```python
            )
            assert session_claims(resp, app)["sub"] == "cust_abc"

```

In `tests/test_device_grant.py`, replace:

```python

            # 4. Poll after approval: issuance is disabled, so no token.
            token_resp = await c.post(
```

with:

```python

            # 4. Poll after approval: a layer-1 session.
            token_resp = await c.post(
```

In `tests/test_device_grant.py`, replace:

```python
            )
        assert token_resp.status_code == 503
        assert token_resp.json() == ISSUANCE_DISABLED_BODY
        assert jwt_shaped_strings(token_resp.text) == []

```

with:

```python
            )
        assert session_claims(token_resp, app)["sub"] == "cust_7f3a"

```

In `tests/test_device_grant.py`, replace:

```python
        bearer for `cust_attacker` approves the code for the attacker, never
        the name in the body. Asserted on the stored `customer_ref`, the value
        `/token` reads, since `/token` has minted nothing from it since
        2026-09-30."""
        async with _client(app) as client:
```

with:

```python
        bearer for `cust_attacker` approves the code for the attacker, never
        the name in the body, on the stored `customer_ref` and on the
        session's `sub`."""
        async with _client(app) as client:
```

In `tests/test_device_grant.py`, replace:

```python

        assert token_resp.status_code == 503
        assert token_resp.json() == ISSUANCE_DISABLED_BODY

```

with:

```python

        assert session_claims(token_resp, app)["sub"] == "cust_attacker"

```

> **Amended 1 October 2026 (review follow-up, commit after Task 6).** The tree adds back the assertion this inversion dropped, narrowed: ``cust_victim`` is absent from the raw body, from the refresh token and the scope, and from every claim except ``client_id`` (where the browser put it, with ``client_id_verified`` false).

In `tests/test_device_grant.py`, replace:

```python
        assert stored.customer_ref == "cust_attacker"
        assert "cust_victim" not in token_resp.text

```

with:

```python
        assert stored.customer_ref == "cust_attacker"

```

In `tests/test_device_grant.py`, replace:

```python
    """Audit finding C-01: aud=payments.svc scope=payments:execute must
    never reach an HTTP client from this endpoint again. Since 2026-09-30
    the same holds for the read token: the approved body carries no token."""

    async def test_approved_exchange_body_has_exactly_the_two_error_keys(
        self, app: Starlette, key_pair: RSAKeyPair
```

with:

```python
    """Audit finding C-01: aud=payments.svc scope=payments:execute must
    never reach an HTTP client from this endpoint again, and since 2026-09-30
    neither may the layer-2 read token: the approved body carries exactly the
    five keys of a layer-1 session."""

    async def test_approved_exchange_body_has_exactly_the_five_session_keys(
        self, app: Starlette, key_pair: RSAKeyPair
```

In `tests/test_device_grant.py`, replace:

```python

        assert resp.status_code == 503
        data = resp.json()
        assert set(data) == {"error", "error_description"}
        assert "write_token" not in data
        assert "access_token" not in data

```

with:

```python

        session_claims(resp, app)
        data = resp.json()
        assert "write_token" not in data
        assert "id_token" not in data

```

In `tests/test_device_grant.py`, replace:

```python

            # The pairing completes as far as issuance, which is disabled.
            issued = await client.post(
```

with:

```python

            issued = await client.post(
```

In `tests/test_device_grant.py`, replace:

```python
            )
            assert issued.status_code == 503
            assert issued.json() == ISSUANCE_DISABLED_BODY

```

with:

```python
            )
            assert session_claims(issued, app)["sub"] == "cust_abc"

```

In `tests/test_device_grant.py`, replace:

```python
class TestASpentDeviceCodeStaysSpent:
    """A code that was spent is refused, and a refused exchange spends nothing.

    UNTIL 2026-09-30 THE EXCHANGE THAT MINTED SPENT THE CODE, and
    ``dev-docs/decisions/0012-device-code-single-use.md`` carries why one
    approved code is worth at most one token: RFC 8628 §5.2 calls what a
    device code redeems an authorization code, and RFC 6749 §10.5 makes those
    "short lived and single-use". Issuance is now disabled pending the layer-1
    session token, so no exchange spends a code, and these tests reach a spent
    code the way a deployment still can: through the store, as a build before
    2026-09-30 left it, in a shared Redis that outlives the deploy.

    The spent-code refusal is therefore the one tested here, together with the
    new property it sits beside: a refused exchange of an approved code leaves
    it unspent, including when two of them race.
    """

    async def test_a_refused_exchange_leaves_the_code_unspent(
        self, app: Starlette, key_pair: RSAKeyPair
    ) -> None:
        """Two polls of one approved code a full interval apart, one answer,
        and nothing spent. The wait is simulated by moving the recorded poll
        back one interval; a poll inside it is ``slow_down`` (pinned in
        ``tests/test_pairing_audit.py``)."""
        async with _client(app) as client:
```

with:

```python
class TestASpentDeviceCodeStaysSpent:
    """A code that was spent is refused, and one approved code is one session.

    THE EXCHANGE THAT ISSUES SPENDS THE CODE, and
    ``dev-docs/decisions/0012-device-code-single-use.md`` carries why one
    approved code is worth at most one grant: RFC 8628 §5.2 calls what a
    device code redeems an authorization code, and RFC 6749 §10.5 makes those
    "short lived and single-use". Most tests here spend the code through the
    store so they are about the refusal and not the mint.
    """

    async def test_an_issued_exchange_spends_the_code_and_a_second_is_refused(
        self, app: Starlette, key_pair: RSAKeyPair
    ) -> None:
        """The first poll after approval is issued a session and spends the
        code; a replay, unpaced because it is terminal, is ``invalid_grant``."""
        async with _client(app) as client:
```

In `tests/test_device_grant.py`, replace:

```python
            first = await _exchange(client, device["device_code"])
            app.state._approved_poll_times[device["device_code"]] -= timedelta(
                seconds=app.state.settings.device_poll_interval_seconds
            )
            second = await _exchange(client, device["device_code"])

        assert first.status_code == second.status_code == 503
        assert first.json() == second.json() == ISSUANCE_DISABLED_BODY
        stored = await app.state.device_code_store.get_device_code(device["device_code"])
        assert stored is not None
        assert stored.exchanged_at is None

```

with:

```python
            first = await _exchange(client, device["device_code"])
            second = await _exchange(client, device["device_code"])

        session_claims(first, app)
        assert second.status_code == 400
        assert second.json()["error"] == "invalid_grant"
        stored = await app.state.device_code_store.get_device_code(device["device_code"])
        assert stored is not None
        assert stored.exchanged_at is not None

```

In `tests/test_device_grant.py`, replace:

```python
            device = await _start_device_grant(client)
            assert (await _approve(app, client, device, bearer(key_pair))).status_code == 200
            assert await store.consume_device_code(device["device_code"]) is True

            replay = await _exchange(client, device["device_code"])
```

with:

```python
            device = await _start_device_grant(client)
            assert (await _approve(app, client, device, bearer(key_pair))).status_code == 200
            assert await store.consume_device_code(device["device_code"], session_id="") is True

            replay = await _exchange(client, device["device_code"])
```

In `tests/test_device_grant.py`, replace:

```python
            device = await _start_device_grant(client)
            assert (await _approve(app, client, device, bearer(key_pair))).status_code == 200
            assert await store.consume_device_code(device["device_code"]) is True

            spent = await _exchange(client, device["device_code"])
```

with:

```python
            device = await _start_device_grant(client)
            assert (await _approve(app, client, device, bearer(key_pair))).status_code == 200
            assert await store.consume_device_code(device["device_code"], session_id="") is True

            spent = await _exchange(client, device["device_code"])
```

In `tests/test_device_grant.py`, replace:

```python
            assert (await _approve(app, client, device, bearer(key_pair))).status_code == 200
            assert await store.consume_device_code(device["device_code"]) is True

```

with:

```python
            assert (await _approve(app, client, device, bearer(key_pair))).status_code == 200
            assert await store.consume_device_code(device["device_code"], session_id="") is True

```

In `tests/test_device_grant.py`, replace:

```python

    async def test_two_concurrent_exchanges_issue_nothing_and_spend_nothing(
        self, app: Starlette, key_pair: RSAKeyPair
    ) -> None:
        """The race this class used to force for the claim, kept for the refusal.

        Until the pacing of approved codes it held two requests inside the
        revocation check with a barrier, so both reached the point where a
        token used to be minted. Now the pacing check lets exactly one through
        (the check and the record have no ``await`` between them), so the
        other is answered ``slow_down`` before the revocation check, and a
        barrier of two would never release. Neither gets a token, and the
        code is still unspent afterwards.
        """
```

with:

```python

    async def test_exactly_one_of_two_concurrent_exchanges_is_issued_a_session(
        self, app: Starlette, key_pair: RSAKeyPair
    ) -> None:
        """Within one process the approved-poll pacing lets exactly one through
        (the check and the record have no ``await`` between them), so the other
        is answered ``slow_down`` before a family is drawn -- or, when the
        first finishes before the second reads the code, the spent code's
        ``invalid_grant``. Either way one session. The two-replica form of the
        race, where both pass the pacing and the claim decides, is in
        ``tests/test_token_session_issuance.py``.
        """
```

In `tests/test_device_grant.py`, replace:

```python

        assert sorted(r.status_code for r in both) == [400, 503]
        by_status = {r.status_code: r for r in both}
        assert by_status[503].json() == ISSUANCE_DISABLED_BODY
        assert by_status[400].json()["error"] == "slow_down"
        assert [jwt_shaped_strings(r.text) for r in both] == [[], []]
        stored = await app.state.device_code_store.get_device_code(device["device_code"])
        assert stored is not None
        assert stored.exchanged_at is None

```

with:

```python

        assert sorted(r.status_code for r in both) == [200, 400]
        by_status = {r.status_code: r for r in both}
        session_claims(by_status[200], app)
        assert by_status[400].json()["error"] in {"slow_down", "invalid_grant"}
        assert jwt_shaped_strings(by_status[400].text) == []

```

> **Amended 1 October 2026 (review follow-up, commit after Task 6).** The tree adds back the two assertions this inversion dropped: the code's ``exchanged_at`` is set, and the in-memory family store holds exactly one family, the one the code's ``session_id`` names.

In `tests/test_device_grant.py`, replace:

```python

        assert await store.consume_device_code(code.device_code) is True
        assert await store.consume_device_code(code.device_code) is False

```

with:

```python

        assert await store.consume_device_code(code.device_code, session_id="") is True
        assert await store.consume_device_code(code.device_code, session_id="") is False

```

In `tests/test_device_grant.py`, replace:

```python

        await store.consume_device_code(code.device_code)

```

with:

```python

        await store.consume_device_code(code.device_code, session_id="")

```

In `tests/test_device_grant.py`, replace:

```python
    ) -> None:
        assert await store.consume_device_code("never-existed") is False

```

with:

```python
    ) -> None:
        assert await store.consume_device_code("never-existed", session_id="") is False

```

In `tests/test_device_grant.py`, replace:

```python
        won = await asyncio.gather(
            store.consume_device_code(code.device_code),
            store.consume_device_code(code.device_code),
        )
```

with:

```python
        won = await asyncio.gather(
            store.consume_device_code(code.device_code, session_id=""),
            store.consume_device_code(code.device_code, session_id=""),
        )
```

In `tests/test_pairing_audit.py`, replace:

```python
off the back of it are both countable and join on
``arguments['device_code_handle']``. Since 2026-09-30 the exchange row is the
``issuance_disabled`` refusal, because ``POST /token`` mints nothing until the
layer-1 session token exists.
``POST /device_authorization`` writes none, deliberately, and
```

with:

```python
off the back of it are both countable and join on
``arguments['device_code_handle']``. The exchange row is the mint of a
layer-1 session, ``returned`` with a NULL ``detail`` and the family's
``session_id`` beside the handle.
``POST /device_authorization`` writes none, deliberately, and
```

In `tests/test_pairing_audit.py`, replace:

```python
from postern_core.auth.device_keys import no_enrolled_devices
from postern_core.auth.revocation import RevocationStoreBase, RevocationStoreUnavailable
```

with:

```python
from postern_core.auth.device_keys import no_enrolled_devices
from postern_core.auth.refresh_sessions import InMemoryRefreshSessionStore
from postern_core.auth.revocation import RevocationStoreBase, RevocationStoreUnavailable
```

In `tests/test_pairing_audit.py`, replace:

```python
    DETAIL_INVALID_SUBJECT,
    DETAIL_ISSUANCE_DISABLED,
    DETAIL_NOT_SCANNED,
```

with:

```python
    DETAIL_INVALID_SUBJECT,
    DETAIL_NOT_SCANNED,
```

In `tests/test_pairing_audit.py`, replace:

```python
from services.confirm.main import create_confirm_app
from services.confirm.settings import ConfirmSettings
from tests.device_grant_helpers import (
    ISSUANCE_DISABLED_BODY,
    jwt_shaped_strings,
```

with:

```python
from services.confirm.main import create_confirm_app
from services.confirm.session_token import SessionClaims, SessionTokenMinter
from services.confirm.settings import ConfirmSettings
from tests.device_grant_helpers import (
    jwt_shaped_strings,
```

In `tests/test_pairing_audit.py`, replace:

```python
    scan_in_store,
)
```

with:

```python
    scan_in_store,
    session_claims,
)
```

In `tests/test_pairing_audit.py`, replace:

```python
    customer no pairing row names: it reads that customer off the code, runs
    the ZT-7 check against them and writes ``issuance_disabled`` rows under
    their name. It hands out no token today only because issuance is
    disabled; the pending session-token change would hand one out.
    """
```

with:

```python
    customer no pairing row names: it reads that customer off the code, runs
    the ZT-7 check against them and issues a session in their name.
    """
```

In `tests/test_pairing_audit.py`, replace:

```python

async def test_an_approved_code_is_refused_503_unspent_and_recorded_as_issuance_disabled(
    app: Starlette, clean: Database, key_pair: RSAKeyPair
) -> None:
    """Issuance is disabled until the layer-1 session token lands.

    The token this endpoint used to return was a layer-2 backend token, signed
    with the read key ``services/api`` publishes, so a public client that
    completed a pairing held a credential the accounts backend accepts. Three
    properties of the refusal that replaced it: the body is the fixed 503, the
    minter is never called, and the code is not spent -- a poll after the
    interval gets the same answer and a second row, not the spent-code
    refusal. The pacing is pinned in the next test.
    """
```

with:

```python

class SignMustNotBeCalled:
    """Stands in for the session minter: ``prepare`` is the real one, and a
    ``sign`` raises and counts. A stand-in rather than ``patch.object`` on the
    app's minter, so the real object is untouched for the next test."""

    def __init__(self, real: SessionTokenMinter) -> None:
        self._real = real
        self.calls = 0

    def prepare(self, **kwargs: Any) -> SessionClaims:
        return self._real.prepare(**kwargs)

    def sign(self, claims: SessionClaims) -> str:
        self.calls += 1
        raise AssertionError("POST /token signed a session it must not issue")


async def test_an_approved_code_is_issued_a_session_spent_and_recorded_as_minted(
    app: Starlette, clean: Database, key_pair: RSAKeyPair
) -> None:
    """One approved code, one session, one ``returned`` row with NULL ``detail``.

    The row names the family by ``session_id``, raw, beside the device code's
    handle, so an operator can revoke that family and join it to the pairing.
    A replay after that is the spent-code refusal and its own row.
    """
```

In `tests/test_pairing_audit.py`, replace:

```python

    class MustNotBeCalled:
        """Stands in for the read minter. A stand-in rather than
        ``patch.object``, because ``InternalTokenMinter`` is a frozen
        dataclass."""

        calls = 0

        def mint(self, **kwargs: Any) -> str:
            MustNotBeCalled.calls += 1
            raise AssertionError("POST /token reached the read minter")

    app.state.read_minter = MustNotBeCalled()

    first = await exchange(app, code.device_code)
    assert first.status_code == 503, first.text
    assert first.json() == ISSUANCE_DISABLED_BODY

```

with:

```python

    first = await exchange(app, code.device_code)
    claims = session_claims(first, app)

```

In `tests/test_pairing_audit.py`, replace:

```python
    assert [r.tool_name for r in written] == [PAIRING_TOOL_NAME, TOKEN_TOOL_NAME]
    refusal = written[1]
    assert refusal.outcome == OUTCOME_RAISED
    assert refusal.detail == DETAIL_ISSUANCE_DISABLED
    assert refusal.customer_ref == CUSTOMER
    assert refusal.arguments["route"] == TOKEN_ROUTE
    assert refusal.arguments["device_code_handle"] == handle_of(code.device_code)

    stored = await unwrap(app.state.device_code_store, code.device_code)
    assert stored.exchanged_at is None, "a refused exchange spent the device code"

    interval_ago(app, code.device_code)
    second = await exchange(app, code.device_code)
    assert second.status_code == 503, second.text
    assert second.json() == ISSUANCE_DISABLED_BODY
    assert [r.detail for r in await rows(clean)][1:] == [DETAIL_ISSUANCE_DISABLED] * 2
    assert MustNotBeCalled.calls == 0

```

with:

```python
    assert [r.tool_name for r in written] == [PAIRING_TOOL_NAME, TOKEN_TOOL_NAME]
    mint = written[1]
    assert mint.outcome == OUTCOME_RETURNED
    assert mint.detail is None
    assert mint.customer_ref == CUSTOMER
    assert mint.arguments["route"] == TOKEN_ROUTE
    assert mint.arguments["device_code_handle"] == handle_of(code.device_code)
    assert mint.arguments["session_id"] == claims["sid"]
    assert set(mint.arguments) == {
        "route",
        "device_code_handle",
        "session_id",
        "client_ip",
        "paired_client_id",
    }

    stored = await unwrap(app.state.device_code_store, code.device_code)
    assert stored.exchanged_at is not None, "an issued exchange left the device code redeemable"
    assert stored.session_id == claims["sid"]

    second = await exchange(app, code.device_code)
    assert second.status_code == 400, second.text
    assert second.json()["error"] == "invalid_grant"
    assert [r.detail for r in await rows(clean)][1:] == [None, DETAIL_DEVICE_CODE_SPENT]

```

In `tests/test_pairing_audit.py`, replace:

```python
) -> None:
    """Two polls inside the interval: the 503 once, then ``slow_down``, one row.

    Without pacing, a client honouring the retryable 503 would come straight
    back at the address-bucket limiter's pace until the code's TTL, each poll
    an ``audit_log`` INSERT and a revocation read. ``Retry-After`` tells it
    the interval, which is the pace this endpoint enforces.
    """
```

with:

```python
) -> None:
    """Two polls inside the interval: the store-full 503 once, then ``slow_down``.

    The pacing governs an approved code that gets a RETRYABLE answer. Without
    it a client honouring the 503 would come straight back at the
    address-bucket limiter's pace until the code's TTL, each poll an
    ``audit_log`` INSERT and a store read. ``Retry-After`` tells it the
    interval, which is the pace this endpoint enforces, and the code stays
    redeemable because the family was never created. No session is signed.
    """
```

In `tests/test_pairing_audit.py`, replace:

```python
    interval = app.state.settings.device_poll_interval_seconds

```

with:

```python
    interval = app.state.settings.device_poll_interval_seconds
    app.state.refresh_session_store = InMemoryRefreshSessionStore(max_sessions=0)
    minter = SignMustNotBeCalled(app.state.session_minter)
    app.state.session_minter = minter

```

In `tests/test_pairing_audit.py`, replace:

```python
    assert first.status_code == 503, first.text
    assert first.json() == ISSUANCE_DISABLED_BODY
    assert first.headers["retry-after"] == str(interval)
```

with:

```python
    assert first.status_code == 503, first.text
    assert first.json()["error"] == "temporarily_unavailable"
    assert first.headers["retry-after"] == str(interval)
```

In `tests/test_pairing_audit.py`, replace:

```python
    token_rows = [r for r in await rows(clean) if r.tool_name == TOKEN_TOOL_NAME]
    assert [r.detail for r in token_rows] == [DETAIL_ISSUANCE_DISABLED]

```

with:

```python
    token_rows = [r for r in await rows(clean) if r.tool_name == TOKEN_TOOL_NAME]
    assert [r.detail for r in token_rows] == ["RefreshSessionStoreFull"]
    assert minter.calls == 0
    stored = await unwrap(app.state.device_code_store, code.device_code)
    assert stored.exchanged_at is None, "a full family store spent the device code"

```

In `tests/test_pairing_audit.py`, replace:

```python

    assert after.status_code == 503, after.text
    assert after.json() == ISSUANCE_DISABLED_BODY

```

with:

```python

    session_claims(after, app)

```

In `tests/test_pairing_audit.py`, replace:

```python
    separately. Both are ``device_grant.*``, neither is a registered MCP tool.
    Since 2026-09-30 the row records the issuance-disabled refusal, because no
    token is minted.
    """
```

with:

```python
    separately. Both are ``device_grant.*``, neither is a registered MCP tool.
    """
```

In `tests/test_pairing_audit.py`, replace:

```python

    resp = await exchange(app, code.device_code)
    assert resp.status_code == 503
    assert "access_token" not in resp.json()

    written = await rows(clean)
```

with:

```python

    resp = await exchange(app, code.device_code)
    session_claims(resp, app)

    written = await rows(clean)
```

In `tests/test_pairing_audit.py`, replace:

```python
    mint = written[1]
    assert mint.outcome == OUTCOME_RAISED
    assert mint.detail == DETAIL_ISSUANCE_DISABLED
    assert mint.customer_ref == CUSTOMER
```

with:

```python
    mint = written[1]
    assert mint.outcome == OUTCOME_RETURNED
    assert mint.detail is None
    assert mint.customer_ref == CUSTOMER
```

In `tests/test_pairing_audit.py`, replace:

```python

    Until 2026-09-30 this took the minted token apart segment by segment and
    asserted none of it was on the row. No token is minted now, so the body
    is asserted to hold nothing JWT-shaped, and the one credential this
    request did carry, the device code, is asserted absent from the row.
    """
```

with:

```python

    The access token is taken apart segment by segment, the refresh token's
    secret likewise, and none of it is on the row; nor is the device code the
    request carried. The family id is there, raw, and that is allowed: it is
    in every access token of the family and selects a record, nothing more.
    """
```

In `tests/test_pairing_audit.py`, replace:

```python
    resp = await exchange(app, code.device_code)
    assert jwt_shaped_strings(resp.text) == []

```

with:

```python
    resp = await exchange(app, code.device_code)
    body = resp.json()

```

In `tests/test_pairing_audit.py`, replace:

```python
    assert jwt_shaped_strings(serialised) == []
    assert code.device_code not in serialised

```

with:

```python
    assert jwt_shaped_strings(serialised) == []
    for segment in body["access_token"].split("."):
        assert segment not in serialised
    assert body["refresh_token"] not in serialised
    assert body["refresh_token"].split(".")[2] not in serialised
    assert code.device_code not in serialised
    assert mint.arguments["session_id"] == body["refresh_token"].split(".")[1]

```

In `tests/test_pairing_audit.py`, replace:

```python

    Since 2026-09-30 the exchange mints nothing, so what fails closed here is
    the issuance-disabled refusal: its row cannot be written, the request
    answers 500, and nothing reaches the caller. The order below is kept
    because the session-token change will mint here again.

    ``/approve`` fails closed by withdrawing the pairing, because the pairing
    is in this deployment's own store. A mint cannot be withdrawn: the token is
    signed and nothing here can revoke it inside its 60-second life. So the
    order is mint, then commit the row, then return -- and the token is only
    ever serialised to a caller after the row is durable. An implementation
```

with:

```python

    ``/approve`` fails closed by withdrawing the pairing, because the pairing
    is in this deployment's own store. A mint cannot be withdrawn: the token is
    signed and nothing here can take it back from a caller once it is
    serialised. So the order is mint, then commit the row, then return -- and the token is only
    ever serialised to a caller after the row is durable. An implementation
```

In `tests/test_pairing_audit.py`, replace:

```python

async def test_a_signing_key_that_would_fail_is_never_reached(
    app: Starlette, clean: Database, key_pair: RSAKeyPair
) -> None:
    """The minter is wired and not called, so its failure cannot surface.

    Until 2026-09-30 this asserted that a mint which raised left a ``raised``
    row naming the exception rather than a ``returned`` row claiming a token.
    Issuance is disabled now, so a minter that raises on every call is the
    sharpest witness that ``/token`` never reaches it: the answer is the
    issuance-disabled 503 and the row says so, with no success row claiming
    a mint.
    """
```

with:

```python

async def test_a_mint_that_raises_leaves_a_raised_row_and_the_code_spent(
    app: Starlette, clean: Database, key_pair: RSAKeyPair
) -> None:
    """A signing key that fails at step 4 of spec section 5.

    The row names the exception rather than a ``returned`` row claiming a
    session, nothing reaches the caller, and the code stays spent with a
    family holding a never-issued ``jti`` -- harmless, and the customer
    re-pairs.
    """
```

In `tests/test_pairing_audit.py`, replace:

```python
    class Unsignable:
        """Stands in for the minter. A stand-in rather than ``patch.object``:
        ``InternalTokenMinter`` is a frozen dataclass, so patching an attribute
        on an instance raises ``FrozenInstanceError`` when the patch unwinds."""

        def mint(self, **kwargs: Any) -> str:
            raise RuntimeError("the signing key source is unavailable")

    app.state.read_minter = Unsignable()

```

with:

```python
    class Unsignable:
        """Stands in for the session minter: the real ``prepare``, and a
        ``sign`` that fails the way an unreachable Vault does."""

        def __init__(self, real: SessionTokenMinter) -> None:
            self._real = real

        def prepare(self, **kwargs: Any) -> SessionClaims:
            return self._real.prepare(**kwargs)

        def sign(self, claims: SessionClaims) -> str:
            raise RuntimeError("the signing key source is unavailable")

    app.state.session_minter = Unsignable(app.state.session_minter)

```

In `tests/test_pairing_audit.py`, replace:

```python

    assert resp.status_code == 503
    assert resp.json() == ISSUANCE_DISABLED_BODY

```

with:

```python

    assert resp.status_code == 500
    assert "access_token" not in resp.text

```

In `tests/test_pairing_audit.py`, replace:

```python
    assert row.outcome == OUTCOME_RAISED, "a row claimed a mint that never happened"
    assert row.detail == DETAIL_ISSUANCE_DISABLED
    assert row.customer_ref == CUSTOMER

```

with:

```python
    assert row.outcome == OUTCOME_RAISED, "a row claimed a mint that never happened"
    assert row.detail == "RuntimeError"
    assert row.customer_ref == CUSTOMER
    stored = await unwrap(app.state.device_code_store, code.device_code)
    assert stored.exchanged_at is not None

```

In `tests/test_pairing_audit.py`, replace:

```python

    SPENT THROUGH THE STORE since 2026-09-30, because no exchange spends a
    code any more; a code an earlier build spent is how this row still
    arises, in a shared store that outlives the deploy.
    """
```

with:

```python

    SPENT THROUGH THE STORE, so the test is about the replay and not the
    mint that would otherwise spend it.
    """
```

In `tests/test_pairing_audit.py`, replace:

```python
    """
    code = await paired(app, key_pair)
    store: DeviceCodeStoreBase = app.state.device_code_store
    assert await store.consume_device_code(code.device_code) is True
    await _wipe(clean)

    replay = await exchange(app, code.device_code)
```

with:

```python
    """
    code = await paired(app, key_pair)
    store: DeviceCodeStoreBase = app.state.device_code_store
    assert await store.consume_device_code(code.device_code, session_id="") is True
    await _wipe(clean)

    replay = await exchange(app, code.device_code)
```

In `tests/test_pairing_audit.py`, replace:

```python
    store: DeviceCodeStoreBase = app.state.device_code_store
    assert await store.consume_device_code(code.device_code) is True
    await _wipe(clean)
```

with:

```python
    store: DeviceCodeStoreBase = app.state.device_code_store
    assert await store.consume_device_code(code.device_code, session_id="") is True
    await _wipe(clean)
```

In `tests/test_qr_pairing_end_to_end.py`, replace:

```python

``POST /token`` ends the flow with a 503 and no token, twice, one interval
apart (a poll inside the interval gets ``slow_down`` and no row), because
issuance is disabled until the layer-1 session token lands: the token it used
to return was a layer-2 backend token, signed with the read key
``services/api`` publishes. This test builds ``services/api`` over the SAME
read key as the confirm service, so a token like that one would verify
against the api's own JWKS, and asserts that no ``/token`` body carries one.

The audit trail is read back at the end: one row each for the scan and the
approval, and one ``issuance_disabled`` row per ``/token`` 503 after the
approval, joined on the device code's handle.
"""
```

with:

```python

``POST /token`` ends the flow with a layer-1 session: an access token whose
audience is the MCP server, signed by the SESSION key, and a refresh token. A
replay of the spent code is refused. The regression this file was written for
still runs: before 30 September 2026 ``/token`` returned a layer-2 backend
token, signed with the read key ``services/api`` publishes, so this test
builds ``services/api`` over a read key of its own and asserts that no
``/token`` body carries a token the api's JWKS verifies, and that every
JWT-shaped string in one is a session token.

The audit trail is read back at the end: one row each for the scan and the
approval, the mint, and the replay, joined on the device code's handle.
"""
```

In `tests/test_qr_pairing_end_to_end.py`, replace:

```python
from dataclasses import replace
from datetime import timedelta
from pathlib import Path
```

with:

```python
from dataclasses import replace
from pathlib import Path
```

In `tests/test_qr_pairing_end_to_end.py`, replace:

```python
from postern_core.auth.device_keys import no_enrolled_devices
from postern_core.identity import CustomerRef
```

with:

```python
from postern_core.auth.device_keys import no_enrolled_devices
from postern_core.auth.revocation import decision_scope
from postern_core.identity import CustomerRef
```

In `tests/test_qr_pairing_end_to_end.py`, replace:

```python
from services.confirm.audit import (
    DETAIL_ISSUANCE_DISABLED,
    DETAIL_NOT_SCANNED,
```

with:

```python
from services.confirm.audit import (
    DETAIL_DEVICE_CODE_SPENT,
    DETAIL_NOT_SCANNED,
```

In `tests/test_qr_pairing_end_to_end.py`, replace:

```python
from tests.device_grant_helpers import (
    ISSUANCE_DISABLED_BODY,
    assert_no_body_carries_a_token_the_api_trusts,
    verifies_against,
```

with:

```python
from tests.device_grant_helpers import (
    assert_no_body_carries_a_token_the_api_trusts,
    session_claims,
    verifies_against,
```

In `tests/test_qr_pairing_end_to_end.py`, replace:

```python
def read_key_pem(tmp_path: Path) -> str:
    """One read key on disk, for BOTH services, as a Vault deployment shares
    transit key ``postern-read`` between them. Without it each app generates
    its own key and no token of confirm's could ever verify against the api's
    JWKS, which would make the regression below pass for the wrong reason."""
    key = RSAKey.generate_key(2048, parameters={"kid": "read-1", "use": "sig", "alg": "RS256"})
```

with:

```python
def read_key_pem(tmp_path: Path) -> str:
    """The api's read key on disk, so the control below can mint with the
    same key the api publishes."""
    key = RSAKey.generate_key(2048, parameters={"kid": "read-1", "use": "sig", "alg": "RS256"})
```

In `tests/test_qr_pairing_end_to_end.py`, replace:

```python
@pytest.fixture()
def app(pg_url: str, read_key_pem: str) -> tuple[Starlette, RSAKeyPair]:
    key_pair = RSAKeyPair.generate()
```

with:

```python
@pytest.fixture()
def app(pg_url: str) -> tuple[Starlette, RSAKeyPair]:
    key_pair = RSAKeyPair.generate()
```

In `tests/test_qr_pairing_end_to_end.py`, replace:

```python
    built = create_confirm_app(
        replace(ConfirmSettings.for_testing(), database_url=pg_url, read_key_pem_path=read_key_pem),
        assertion_verifier=verifier,
```

with:

```python
    built = create_confirm_app(
        replace(ConfirmSettings.for_testing(), database_url=pg_url),
        assertion_verifier=verifier,
```

In `tests/test_qr_pairing_end_to_end.py`, replace:

```python
@pytest.fixture()
async def api_jwks(read_key_pem: str) -> dict[str, Any]:
    """The key set ``services/api`` publishes at ``/.well-known/jwks.json``,
    fetched over ASGI from the assembled app: the set Istio trusts."""
    api = create_api_app(
        replace(ApiSettings.for_testing(), read_key_pem_path=read_key_pem),
```

with:

```python
@pytest.fixture()
async def api(read_key_pem: str) -> tuple[Any, dict[str, Any]]:
    """An assembled ``services/api`` and the key set it publishes at
    ``/.well-known/jwks.json``, fetched over ASGI: the set Istio trusts."""
    built = create_api_app(
        replace(ApiSettings.for_testing(), read_key_pem_path=read_key_pem),
```

In `tests/test_qr_pairing_end_to_end.py`, replace:

```python
    async with httpx2.AsyncClient(
        transport=httpx2.ASGITransport(app=api), base_url="http://api.test"
    ) as client:
        async with api.router.lifespan_context(api):
            published = await client.get("/.well-known/jwks.json")
```

with:

```python
    async with httpx2.AsyncClient(
        transport=httpx2.ASGITransport(app=built), base_url="http://api.test"
    ) as client:
        async with built.router.lifespan_context(built):
            published = await client.get("/.well-known/jwks.json")
```

In `tests/test_qr_pairing_end_to_end.py`, replace:

```python
    jwks: dict[str, Any] = published.json()
    return jwks

```

with:

```python
    jwks: dict[str, Any] = published.json()
    return built, jwks

```

In `tests/test_qr_pairing_end_to_end.py`, replace:

```python
async def test_a_browser_and_a_phone_complete_a_pairing_through_every_route(
    app: tuple[Starlette, RSAKeyPair], clean: Database, api_jwks: dict[str, Any]
) -> None:
    confirm, key_pair = app
    assertion = key_pair.create_token(
```

with:

```python
async def test_a_browser_and_a_phone_complete_a_pairing_through_every_route(
    app: tuple[Starlette, RSAKeyPair], clean: Database, api: tuple[Any, dict[str, Any]]
) -> None:
    confirm, key_pair = app
    api_app, api_jwks = api
    assertion = key_pair.create_token(
```

In `tests/test_qr_pairing_end_to_end.py`, replace:

```python
        )
        too_soon = await browser.post(
            "/token", data={"grant_type": "device_code", "device_code": grant["device_code"]}
        )
        # The browser waits one interval, as the 503's Retry-After tells it
        # to; simulated by moving the recorded poll back rather than sleeping.
        confirm.state._approved_poll_times[grant["device_code"]] -= timedelta(
            seconds=int(token.headers["retry-after"])
        )
        second = await browser.post(
            "/token", data={"grant_type": "device_code", "device_code": grant["device_code"]}
        )

    # THE CONTROL THAT MAKES THE REGRESSION MEAN SOMETHING. The read minter is
    # still wired, and what it signs verifies against the api's published
    # JWKS: that is exactly the layer-2 token /token used to hand out. If this
    # stopped verifying, the assertion below would pass for any body at all.
    backend_token = confirm.state.read_minter.mint(
        subject=CustomerRef(value=CUSTOMER), audience="accounts.svc", scope="accounts:read"
    )
    assert verifies_against(backend_token, api_jwks)
```

with:

```python
        )
        replay = await browser.post(
            "/token", data={"grant_type": "device_code", "device_code": grant["device_code"]}
        )
        session_jwks = (await browser.get("/session/jwks.json")).json()

    # THE CONTROL THAT MAKES THE REGRESSION MEAN SOMETHING. A token the api's
    # own read minter signs verifies against the api's published JWKS: that is
    # exactly the layer-2 token /token used to hand out. If this stopped
    # verifying, the assertion below would pass for any body at all.
    with decision_scope(False):
        backend_token = api_app.state.backend_client._minter(
            CustomerRef(value=CUSTOMER), "accounts.svc"
        )
    assert verifies_against(backend_token, api_jwks)
```

In `tests/test_qr_pairing_end_to_end.py`, replace:

```python
    # on the property that matters rather than on a status code.
    assert_no_body_carries_a_token_the_api_trusts(
        [token.text, too_soon.text, second.text], api_jwks
    )

    # Issuance is disabled: the same 503 twice, because the code is not spent,
    # with a poll inside the interval answered slow_down in between.
    assert token.status_code == 503, token.text
    assert token.json() == ISSUANCE_DISABLED_BODY
    assert token.headers["retry-after"] == str(confirm.state.settings.device_poll_interval_seconds)
    assert too_soon.status_code == 400, too_soon.text
    assert too_soon.json()["error"] == "slow_down"
    assert second.status_code == 503, second.text
    assert second.json() == ISSUANCE_DISABLED_BODY
    stored = await confirm.state.device_code_store.get_device_code(grant["device_code"])
    assert stored is not None
    assert stored.exchanged_at is None, "a refused /token spent the device code"

```

with:

```python
    # on the property that matters rather than on a status code.
    settings = confirm.state.settings
    assert_no_body_carries_a_token_the_api_trusts(
        [token.text, replay.text],
        api_jwks,
        session_jwks,
        issuer=settings.session_token_issuer,
        audience=settings.session_token_audience,
    )

    claims = session_claims(token, confirm)
    assert claims["sub"] == CUSTOMER
    assert claims["client_id"] == "claude-code"
    assert replay.status_code == 400, replay.text
    assert replay.json()["error"] == "invalid_grant"
    stored = await confirm.state.device_code_store.get_device_code(grant["device_code"])
    assert stored is not None
    assert stored.exchanged_at is not None
    assert stored.session_id == claims["sid"]

```

> **Amended 1 October 2026 (review follow-up, commit after Task 6).** The tree also fetches confirm's ``/.well-known/jwks.json``, passes it to the e2e helper as ``write_jwks``, and asserts directly that the access token is signed by no key in the api's read JWKS or in that write JWKS, and by a key in ``/session/jwks.json``.

In `tests/test_qr_pairing_end_to_end.py`, replace:

```python
        (PAIRING_TOOL_NAME, OUTCOME_RETURNED, None),
        (TOKEN_TOOL_NAME, OUTCOME_RAISED, DETAIL_ISSUANCE_DISABLED),
        (TOKEN_TOOL_NAME, OUTCOME_RAISED, DETAIL_ISSUANCE_DISABLED),
    ]
```

with:

```python
        (PAIRING_TOOL_NAME, OUTCOME_RETURNED, None),
        (TOKEN_TOOL_NAME, OUTCOME_RETURNED, None),
        (TOKEN_TOOL_NAME, OUTCOME_RAISED, DETAIL_DEVICE_CODE_SPENT),
    ]
```

In `tests/test_qr_pairing_end_to_end.py`, replace:

```python
        (PAIRING_TOOL_NAME, None),
    ]
    chain = successes + [r for r in written if r.tool_name == TOKEN_TOOL_NAME]
    assert len({r.arguments["device_code_handle"] for r in chain}) == 1
```

with:

```python
        (PAIRING_TOOL_NAME, None),
        (TOKEN_TOOL_NAME, None),
    ]
    chain = [
        r for r in written if r.tool_name != PAIRING_TOOL_NAME or r.outcome == OUTCOME_RETURNED
    ]
    assert len({r.arguments["device_code_handle"] for r in chain}) == 1
    assert successes[2].arguments["session_id"] == claims["sid"]
```

In `tests/test_redis_backed_stores.py`, replace:

```python

    assert await store.consume_device_code(code.device_code) is True
    assert await store.consume_device_code(code.device_code) is False

```

with:

```python

    assert await store.consume_device_code(code.device_code, session_id="") is True
    assert await store.consume_device_code(code.device_code, session_id="") is False

```

In `tests/test_redis_backed_stores.py`, replace:

```python
    won = await asyncio.gather(
        store.consume_device_code(code.device_code),
        store.consume_device_code(code.device_code),
    )
```

with:

```python
    won = await asyncio.gather(
        store.consume_device_code(code.device_code, session_id=""),
        store.consume_device_code(code.device_code, session_id=""),
    )
```

In `tests/test_redis_backed_stores.py`, replace:

```python
    before = await store._redis.ttl(store._key(code.device_code))

    assert await store.consume_device_code(code.device_code) is True

    after = await store._redis.ttl(store._key(code.device_code))
```

with:

```python
    before = await store._redis.ttl(store._key(code.device_code))

    assert await store.consume_device_code(code.device_code, session_id="") is True

    after = await store._redis.ttl(store._key(code.device_code))
```

In `tests/test_redis_backed_stores.py`, replace:

```python

    assert await store.consume_device_code("never-existed") is False
    assert await store._redis.exists(store._key("never-existed")) == 0
```

with:

```python

    assert await store.consume_device_code("never-existed", session_id="") is False
    assert await store._redis.exists(store._key("never-existed")) == 0
```

In `tests/test_redis_backed_stores.py`, replace:

```python

    assert await store.consume_device_code(code.device_code) is True

```

with:

```python

    assert await store.consume_device_code(code.device_code, session_id="") is True

```

In `tests/test_redis_backed_stores.py`, replace:

```python
    await store.approve_scanned(code.device_code, OTHER)
    await store.consume_device_code(code.device_code)
    before = await store._redis.get(store._key(code.device_code))
```

with:

```python
    await store.approve_scanned(code.device_code, OTHER)
    await store.consume_device_code(code.device_code, session_id="")
    before = await store._redis.get(store._key(code.device_code))
```

In `tests/test_scan.py`, replace:

```python
    assert await device_store_of(app).approve_scanned(code.device_code, BOB) is True
    assert await device_store_of(app).consume_device_code(code.device_code) is True
    before = await device_store_of(app).get_device_code(code.device_code)
```

with:

```python
    assert await device_store_of(app).approve_scanned(code.device_code, BOB) is True
    assert await device_store_of(app).consume_device_code(code.device_code, session_id="") is True
    before = await device_store_of(app).get_device_code(code.device_code)
```

In `tests/test_scan_network_signal.py`, replace:

```python
    DETAIL_ALREADY_SCANNED,
    DETAIL_ISSUANCE_DISABLED,
    DETAIL_QR_INVALID,
```

with:

```python
    DETAIL_ALREADY_SCANNED,
    DETAIL_QR_INVALID,
```

In `tests/test_scan_network_signal.py`, replace:

```python
    )
    assert token.status_code == 503

```

with:

```python
    )
    assert token.status_code == 200, token.text

```

In `tests/test_scan_network_signal.py`, replace:

```python
    assert approved_mine.risk_signals is None
    assert token_row.detail == DETAIL_ISSUANCE_DISABLED
    assert token_row.risk_signals is None
```

with:

```python
    assert approved_mine.risk_signals is None
    assert token_row.detail is None
    assert token_row.risk_signals is None
```

Create `tests/test_token_session_issuance.py` with:

```python
"""``POST /token`` with ``grant_type=device_code`` issues a layer-1 session.

Spec section 5 of ``dev-docs/device-grant-session-token-spec.md``, through the
assembled confirm app: the five keys and the two headers, a token that
verifies against ``/session/jwks.json``, the ``resource`` parameter, a full
family store, a lost claim, a revocation that predates the approval, and the
reserved ``client_id``. The hotfix's 503 path is gone.
"""

from __future__ import annotations

import asyncio
import dataclasses
import logging
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

import httpx2
import pytest
from fastmcp.server.auth.providers.jwt import JWTVerifier, RSAKeyPair
from joserfc import jwt
from joserfc.jwk import KeySet
from postern_core.auth.device_codes import (
    DeviceCode,
    DeviceCodeStoreBase,
    InMemoryDeviceCodeStore,
    RedisDeviceCodeStore,
)
from postern_core.auth.device_keys import no_enrolled_devices
from postern_core.auth.refresh_sessions import (
    InMemoryRefreshSessionStore,
    RefreshSessionStoreBase,
    ms_of,
)
from postern_core.auth.revocation import InMemoryRevocationStore
from postern_core.store.engine import Database
from postern_core.store.models import OUTCOME_RAISED, AuditEntry
from sqlalchemy import select
from starlette.applications import Starlette

import services.confirm.device_auth as device_auth
from services.confirm.audit import (
    DETAIL_DEVICE_CODE_SPENT,
    DETAIL_REVOKED,
    TOKEN_TOOL_NAME,
    PairingAudit,
)
from services.confirm.main import create_confirm_app
from services.confirm.settings import ConfirmSettings
from tests.device_grant_helpers import scan_in_store, session_claims
from tests.fixtures.append_only_bypass import (
    delete_audit_rows_by_bypassing_the_append_only_triggers,
)
from tests.test_device_grant import AUDIENCE, ISSUER, bearer

CUSTOMER = "cust_7f3a"
RESOURCE = "https://mcp.postern.test/mcp"


@pytest.fixture(scope="module")
def key_pair() -> RSAKeyPair:
    return RSAKeyPair.generate()


@pytest.fixture()
async def clean(database: Database) -> AsyncIterator[Database]:
    async with database.sessionmaker() as s:
        await delete_audit_rows_by_bypassing_the_append_only_triggers(s)
        await s.commit()
    yield database


def _app(key_pair: RSAKeyPair, pg_url: str, **overrides: Any) -> Starlette:
    fields: dict[str, Any] = {
        "database_url": pg_url,
        "session_token_audience": RESOURCE,
        "allow_non_uri_audience": False,
    }
    fields.update(overrides)
    settings = dataclasses.replace(ConfirmSettings.for_testing(), **fields)
    return create_confirm_app(
        settings,
        assertion_verifier=JWTVerifier(
            public_key=key_pair.public_key, issuer=ISSUER, audience=AUDIENCE
        ),
        device_key_store=no_enrolled_devices(),
    )


@pytest.fixture()
def app(key_pair: RSAKeyPair, pg_url: str) -> Starlette:
    return _app(key_pair, pg_url)


def _client(app: Starlette) -> httpx2.AsyncClient:
    return httpx2.AsyncClient(transport=httpx2.ASGITransport(app=app), base_url="http://t")


async def _approved(app: Starlette, key_pair: RSAKeyPair, **body: str) -> dict[str, Any]:
    """A device grant started, scanned in the store and approved for `CUSTOMER`."""
    async with _client(app) as client:
        started = await client.post(
            "/device_authorization", json={"client_id": "claude-code", **body}
        )
        assert started.status_code == 200, started.text
        device: dict[str, Any] = started.json()
        await scan_in_store(app, device["user_code"], CUSTOMER)
        approved = await client.post(
            "/approve", json={"user_code": device["user_code"]}, headers=bearer(key_pair)
        )
        assert approved.status_code == 200, approved.text
    return device


async def _exchange(app: Starlette, device_code: str, **extra: Any) -> httpx2.Response:
    async with _client(app) as client:
        return await client.post(
            "/token", data={"grant_type": "device_code", "device_code": device_code, **extra}
        )


async def _token_rows(db: Database) -> list[AuditEntry]:
    async with db.sessionmaker() as s:
        result = await s.execute(
            select(AuditEntry)
            .where(AuditEntry.tool_name == TOKEN_TOOL_NAME)
            .order_by(AuditEntry.id)
        )
        return list(result.scalars())


class TestTheSuccessResponse:
    async def test_five_keys_two_headers_and_a_token_the_session_jwks_verifies(
        self, app: Starlette, key_pair: RSAKeyPair, clean: Database
    ) -> None:
        device = await _approved(app, key_pair)
        response = await _exchange(app, device["device_code"])
        claims = session_claims(response, app)
        async with _client(app) as client:
            published = (await client.get("/session/jwks.json")).json()
        verified = jwt.decode(response.json()["access_token"], KeySet.import_key_set(published))
        assert verified.claims["jti"] == claims["jti"]
        assert claims["aud"] == RESOURCE
        assert claims["sub"] == CUSTOMER

    async def test_the_scope_is_canonical(
        self, app: Starlette, key_pair: RSAKeyPair, clean: Database
    ) -> None:
        device = await _approved(app, key_pair, scopes="cards:read  accounts:read cards:read")
        response = await _exchange(app, device["device_code"])
        assert session_claims(response, app)["scope"] == "accounts:read cards:read"
        assert response.json()["scope"] == "accounts:read cards:read"

    async def test_the_family_names_the_access_token_it_issued(
        self, app: Starlette, key_pair: RSAKeyPair, clean: Database
    ) -> None:
        device = await _approved(app, key_pair)
        claims = session_claims(await _exchange(app, device["device_code"]), app)
        family = await app.state.refresh_session_store.get(claims["sid"])
        assert family is not None
        assert family.customer_ref == CUSTOMER
        assert family.client_id == "claude-code"
        assert family.generation == 0
        assert [jti for jti, _ in family.access_tokens] == [claims["jti"]]
        assert family.expires_at - family.created_at == timedelta(hours=1)

    async def test_every_token_response_carries_no_store_and_no_cache(
        self, app: Starlette, key_pair: RSAKeyPair
    ) -> None:
        async with _client(app) as client:
            pending = await client.post(
                "/token", data={"grant_type": "device_code", "device_code": "unknown"}
            )
            wrong = await client.post("/token", data={"grant_type": "password"})
        for response in (pending, wrong):
            assert response.headers["cache-control"] == "no-store"
            assert response.headers["pragma"] == "no-cache"

    def test_the_hotfix_path_is_gone(self) -> None:
        assert not hasattr(device_auth, "DETAIL_ISSUANCE_DISABLED")


class TestTheResourceParameter:
    @pytest.mark.parametrize(
        "resource",
        [
            RESOURCE,
            "HTTPS://MCP.Postern.Test/mcp",
            "https://mcp.postern.test:443/mcp",
        ],
    )
    async def test_an_equal_resource_after_normalization_is_served(
        self, app: Starlette, key_pair: RSAKeyPair, clean: Database, resource: str
    ) -> None:
        device = await _approved(app, key_pair)
        session_claims(await _exchange(app, device["device_code"], resource=resource), app)

    @pytest.mark.parametrize(
        "resource",
        [
            "https://mcp.postern.test/mcp/",
            "https://mcp.postern.test/MCP",
            "https://mcp.postern.test/mcp#frag",
            "/mcp",
            "https://other.postern.test/mcp",
        ],
    )
    async def test_any_other_resource_is_invalid_target_with_no_row(
        self, app: Starlette, key_pair: RSAKeyPair, clean: Database, resource: str
    ) -> None:
        device = await _approved(app, key_pair)
        response = await _exchange(app, device["device_code"], resource=resource)
        assert response.status_code == 400
        assert response.json()["error"] == "invalid_target"
        assert await _token_rows(clean) == []
        stored = await app.state.device_code_store.get_device_code(device["device_code"])
        assert stored.exchanged_at is None

    async def test_a_repeated_resource_is_invalid_target(
        self, app: Starlette, key_pair: RSAKeyPair, clean: Database
    ) -> None:
        device = await _approved(app, key_pair)
        async with _client(app) as client:
            response = await client.post(
                "/token",
                content=(
                    f"grant_type=device_code&device_code={device['device_code']}"
                    f"&resource={RESOURCE}&resource={RESOURCE}"
                ),
                headers={"content-type": "application/x-www-form-urlencoded"},
            )
        assert response.status_code == 400
        assert response.json()["error"] == "invalid_target"

    async def test_an_empty_path_normalizes_to_slash(
        self, key_pair: RSAKeyPair, pg_url: str, clean: Database
    ) -> None:
        app = _app(key_pair, pg_url, session_token_audience="https://mcp.postern.test/")  # noqa: S106
        device = await _approved(app, key_pair)
        response = await _exchange(app, device["device_code"], resource="https://mcp.postern.test")
        session_claims(response, app)


class TestAFullFamilyStore:
    async def test_it_answers_503_with_retry_after_and_leaves_the_code_redeemable(
        self, app: Starlette, key_pair: RSAKeyPair, clean: Database
    ) -> None:
        device = await _approved(app, key_pair)
        real: RefreshSessionStoreBase = app.state.refresh_session_store
        app.state.refresh_session_store = InMemoryRefreshSessionStore(max_sessions=0)
        full = await _exchange(app, device["device_code"])
        assert full.status_code == 503
        assert full.headers["retry-after"] == str(app.state.settings.device_poll_interval_seconds)
        stored = await app.state.device_code_store.get_device_code(device["device_code"])
        assert stored.exchanged_at is None

        app.state.refresh_session_store = real
        app.state._approved_poll_times[device["device_code"]] -= timedelta(seconds=60)
        session_claims(await _exchange(app, device["device_code"]), app)
        assert [r.detail for r in await _token_rows(clean)] == ["RefreshSessionStoreFull", None]


class TestALostClaim:
    async def test_two_replicas_racing_one_code_issue_one_session_and_orphan_nothing(
        self, key_pair: RSAKeyPair, pg_url: str, clean: Database
    ) -> None:
        """Both replicas pass their own pacing (the maps are per process), so the
        claim decides; the loser discards the family it created."""
        first = _app(key_pair, pg_url)
        second = _app(key_pair, pg_url)
        second.state.device_code_store = first.state.device_code_store
        second.state.refresh_session_store = first.state.refresh_session_store
        device = await _approved(first, key_pair)

        answers = await asyncio.gather(
            _exchange(first, device["device_code"]),
            _exchange(second, device["device_code"]),
        )

        assert sorted(r.status_code for r in answers) == [200, 400]
        loser = next(r for r in answers if r.status_code == 400)
        assert loser.json()["error"] == "invalid_grant"
        sessions: InMemoryRefreshSessionStore = first.state.refresh_session_store
        assert len(sessions._sessions) == 1, "the losing exchange left an orphaned family"
        details = {r.detail for r in await _token_rows(clean)}
        assert details == {DETAIL_DEVICE_CODE_SPENT, None}

    async def test_a_failing_discard_is_logged_and_tolerated(
        self,
        app: Starlette,
        key_pair: RSAKeyPair,
        clean: Database,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        device = await _approved(app, key_pair)
        store: InMemoryDeviceCodeStore = app.state.device_code_store
        sessions: InMemoryRefreshSessionStore = app.state.refresh_session_store

        async def lost(device_code: str, *, session_id: str) -> bool:
            return False

        async def broken(sid: str) -> None:
            raise ConnectionError("redis went away")

        monkeypatch.setattr(store, "consume_device_code", lost)
        monkeypatch.setattr(sessions, "discard", broken)
        with caplog.at_level(logging.WARNING, logger="services.confirm.device_auth"):
            response = await _exchange(app, device["device_code"])

        assert response.status_code == 400
        assert response.json()["error"] == "invalid_grant"
        (orphan,) = sessions._sessions
        assert f"orphaned session family {orphan}" in caplog.text
        assert "ConnectionError" in caplog.text
        assert [r.detail for r in await _token_rows(clean)] == [DETAIL_DEVICE_CODE_SPENT]


class TestARevocationThatPredatesTheApproval:
    async def _stamp(self, app: Starlette, device_code: str, offset_ms: int) -> None:
        """A customer revocation stamped ``offset_ms`` from the approval, since restored."""
        code: DeviceCode | None = await app.state.device_code_store.get_device_code(device_code)
        assert code is not None and code.approved_at is not None
        store: InMemoryRevocationStore = app.state.postern_revocation_store
        store._revoked_at[CUSTOMER] = (ms_of(code.approved_at) + offset_ms, 2**62)

    async def test_a_restored_revocation_after_the_approval_still_refuses(
        self, app: Starlette, key_pair: RSAKeyPair, clean: Database
    ) -> None:
        device = await _approved(app, key_pair)
        store: InMemoryRevocationStore = app.state.postern_revocation_store
        await store.revoke_customer_client(customer_ref=CUSTOMER, client_id="vendor-x")
        await store.restore_customer_client(customer_ref=CUSTOMER, client_id="vendor-x")
        assert await store.is_customer_revoked(CUSTOMER) is False

        response = await _exchange(app, device["device_code"])

        assert response.status_code == 400
        assert response.json()["error"] == "access_denied"
        (row,) = await _token_rows(clean)
        assert (row.outcome, row.detail) == (OUTCOME_RAISED, DETAIL_REVOKED)

    @pytest.mark.parametrize(("offset_ms", "refused"), [(-2000, True), (-2001, False)])
    async def test_the_two_second_tolerance_at_both_edges(
        self,
        app: Starlette,
        key_pair: RSAKeyPair,
        clean: Database,
        offset_ms: int,
        refused: bool,
    ) -> None:
        device = await _approved(app, key_pair)
        await self._stamp(app, device["device_code"], offset_ms)
        response = await _exchange(app, device["device_code"])
        if refused:
            assert response.json()["error"] == "access_denied"
        else:
            session_claims(response, app)


class TestTheReservedClientId:
    async def test_a_pairing_named_dash_is_refused(self, app: Starlette) -> None:
        async with _client(app) as client:
            response = await client.post("/device_authorization", json={"client_id": "-"})
        assert response.status_code == 400
        assert response.json()["error"] == "invalid_request"

    async def test_a_name_containing_a_dash_is_fine(self, app: Starlette) -> None:
        async with _client(app) as client:
            response = await client.post("/device_authorization", json={"client_id": "a-b"})
        assert response.status_code == 200


class TestTheRowNamesTheFamily:
    def test_the_arguments_keys_come_in_the_documented_order(self) -> None:
        audit = PairingAudit(
            db=None,  # type: ignore[arg-type]
            call_id="c",
            at=datetime.now(UTC),
            started=0.0,
            subject=CUSTOMER,
            claims={},
            client_ip_value="198.51.100.7",
        )
        audit.names(paired_client_id="claude-code")
        audit.names(session_id="s" * 22)
        audit.names(device_code="d" * 43)
        assert list(audit._arguments()) == [
            "route",
            "device_code_handle",
            "session_id",
            "client_ip",
            "paired_client_id",
        ]


@pytest.fixture(params=["memory", "redis"])
async def device_store(request: pytest.FixtureRequest) -> AsyncIterator[DeviceCodeStoreBase]:
    if request.param == "memory":
        yield InMemoryDeviceCodeStore()
        return
    store = RedisDeviceCodeStore(
        url=request.getfixturevalue("redis_url"), key_prefix=f"ts{uuid4().hex[:12]}:"
    )
    yield store
    await store.close()


class TestTheClaimRecordsTheFamily:
    async def test_consume_writes_the_session_id_with_exchanged_at(
        self, device_store: DeviceCodeStoreBase
    ) -> None:
        code = await device_store.create_device_code(
            client_id="c", scopes="accounts:read", verification_uri="https://a.test/verify"
        )
        assert await device_store.consume_device_code(code.device_code, session_id="sid-1")
        assert not await device_store.consume_device_code(code.device_code, session_id="sid-2")
        stored = await device_store.get_device_code(code.device_code)
        assert stored is not None
        assert stored.exchanged_at is not None
        assert stored.session_id == "sid-1"

    def test_a_record_without_the_field_reads_as_empty(self) -> None:
        code = DeviceCode(
            device_code="legacy",
            user_code="ABCDEF",
            verification_uri="https://a.test/verify",
            expires_at=datetime.now(UTC) + timedelta(minutes=5),
        )
        legacy = code.to_dict()
        del legacy["session_id"]
        assert DeviceCode.from_dict(legacy).session_id == ""
```

> **Amended 1 October 2026 (review follow-up, commit after Task 6).** The file in the tree has eleven more test functions than this block (three new classes, two more in ``TestALostClaim``), and the full-store test also asserts that its row names no ``session_id``. ``create`` raising ``ConnectionError``, ``TimeoutError`` or a redis-py ``ConnectionError``/``TimeoutError`` answers a retryable 503 with ``Retry-After``, leaves the code unspent and writes a row under the class name with no ``session_id``; a ``RefreshSessionCollision`` is a 500 with the code unspent. ``consume_device_code`` raising discards the family (a failing discard is logged) and records the claim's exception. A lost claim's row carries the discarded family's ``session_id`` and a replay's carries none. Both RFC 6749 section 5.1 headers appear on an unknown code, a wrong grant type, a forced 500, the limiter's refusal and a 413. On ``/token`` the limiter answers 400 ``slow_down``, never 429, so that refusal is the one tested.

In `tests/test_zt7_confirm_revocation.py`, replace:

```python
from services.confirm.settings import ConfirmSettings
from tests.device_grant_helpers import ISSUANCE_DISABLED_BODY, scan_in_store
from tests.fixtures.append_only_bypass import (
```

with:

```python
from services.confirm.settings import ConfirmSettings
from tests.device_grant_helpers import scan_in_store, session_claims
from tests.fixtures.append_only_bypass import (
```

In `tests/test_zt7_confirm_revocation.py`, replace:

```python

    ZT-7's bar is that a revoked identity stops OBTAINING access. Since
    2026-09-30 ``/token`` issues nothing to anyone (issuance is disabled
    pending the layer-1 session token), so what this pins is the ORDER: the
    revocation check still runs before the issuance refusal, so a revoked
    customer's code is answered ``access_denied`` and not the 503 every other
    approved code gets. Both directions in one test: before the revocation a
    code gets the issuance-disabled 503, after it another gets
    ``access_denied``.

    TWO CODES, kept from when a successful exchange spent the code
    (`dev-docs/decisions/0012-device-code-single-use.md`). Both codes are
```

with:

```python

    ZT-7's bar is that a revoked identity stops OBTAINING access. Both
    directions in one test: before the revocation a code is issued a
    session, after it another is answered ``access_denied`` and issued
    nothing.

    TWO CODES, because a successful exchange spends the code
    (`dev-docs/decisions/0012-device-code-single-use.md`). Both codes are
```

In `tests/test_zt7_confirm_revocation.py`, replace:

```python
    )
    assert served.status_code == 503, served.text
    assert served.json() == ISSUANCE_DISABLED_BODY

```

with:

```python
    )
    assert session_claims(served, app)["sub"] == OWNER

```

In `tests/test_zt7_confirm_revocation.py`, replace:

```python
    assert "access_token" not in response.json()
    # The outage's own 503, not the issuance-disabled one: the revocation
    # check still runs before the issuance refusal.
    assert response.json() != ISSUANCE_DISABLED_BODY

```

with:

```python
    assert "access_token" not in response.json()
    # The outage's own 503, with the poll interval as its Retry-After so a
    # client honouring it is never answered slow_down.
    assert response.json()["error_description"] == (
        "authorization state cannot be checked; retry shortly"
    )
    assert response.headers["retry-after"] == str(app.state.settings.device_poll_interval_seconds)

```

- [ ] **Step 2: Run them to verify they fail**

Run: `uv run pytest tests/test_confirm_rate_limit.py tests/test_device_code_pairing_store.py tests/test_device_code_scanner_ip.py tests/test_device_grant.py tests/test_pairing_audit.py tests/test_qr_pairing_end_to_end.py tests/test_redis_backed_stores.py tests/test_scan.py tests/test_scan_network_signal.py tests/test_token_session_issuance.py tests/test_zt7_confirm_revocation.py -q`

Expected: FAIL, `68 failed, 471 passed`. The first failure reads `AssertionError: {"error":"temporarily_unavailable","error_description":"session token issuance is not enabled"}`.

- [ ] **Step 3: Implement**

In `dev-docs/device-grant-session-token-spec.md`, run exactly:

```bash
perl -pi -e 's/`tests\/test_pairing_audit\.py::(test_an_approved_code_is_refused_503_unspent_and_recorded_as_issuance_disabled)`;/`$1` in `tests\/test_pairing_audit.py` (renamed by this change, so no longer an anchored citation);/' dev-docs/device-grant-session-token-spec.md
```

In `packages/postern-core/src/postern_core/auth/device_codes.py`, replace:

```python
            recorded no scanner address. Recorded only; nothing reads it back.

```

with:

```python
            recorded no scanner address. Recorded only; nothing reads it back.
        session_id: The refresh family ``POST /token`` created for this code,
            written by ``consume_device_code`` in the same compare-and-set as
            ``exchanged_at``. ``POST /scan`` reads it to recall a family a
            session swap produced. Empty until exchanged, and on a record an
            earlier release wrote.

```

In `packages/postern-core/src/postern_core/auth/device_codes.py`, replace:

```python
    scanner_ip: str | None = None

```

with:

```python
    scanner_ip: str | None = None
    session_id: str = ""

```

In `packages/postern-core/src/postern_core/auth/device_codes.py`, replace:

```python
    @abstractmethod
    async def consume_device_code(self, device_code: str) -> bool:
        """Claim a device code for one token exchange. ``True`` to one caller only.

        Sets ``exchanged_at`` on a code that has none and answers ``True``;
        answers ``False`` for a code this store does not hold and for one
```

with:

```python
    @abstractmethod
    async def consume_device_code(self, device_code: str, *, session_id: str) -> bool:
        """Claim a device code for one token exchange. ``True`` to one caller only.

        Sets ``exchanged_at`` and ``session_id`` on a code that has none, in
        one write, and answers ``True``;
        answers ``False`` for a code this store does not hold and for one
```

In `packages/postern-core/src/postern_core/auth/device_codes.py`, replace:

```python
        preference. The caller is `services/confirm/device_auth.py`'s
        ``token_endpoint``, which mints a read token only for the caller that
        wins here. A backend that read the code, awaited anything, and then
```

with:

```python
        preference. The caller is `services/confirm/device_auth.py`'s
        ``token_endpoint``, which issues a session only to the caller that
        wins here. A backend that read the code, awaited anything, and then
```

In `packages/postern-core/src/postern_core/auth/device_codes.py`, replace:

```python
        already chose for the endpoint before this one.
        """
```

with:

```python
        already chose for the endpoint before this one.

        ``session_id`` IS REQUIRED, for the reason ``claim_scan`` gives for
        ``scanner_ip``: it is the refresh family ``POST /token`` created for
        this exchange, and ``POST /scan`` finds that family through it to
        recall a session swap. Written in the same write as ``exchanged_at``,
        so once a scan sees the code exchanged it sees the family too.
        """
```

In `packages/postern-core/src/postern_core/auth/device_codes.py`, replace:

```python
        return _live_match(code, "user_code", user_code)

    async def consume_device_code(self, device_code: str) -> bool:
        """Claim this code for one exchange. ``True`` to one caller only.

```

with:

```python
        return _live_match(code, "user_code", user_code)

    async def consume_device_code(self, device_code: str, *, session_id: str) -> bool:
        """Claim this code for one exchange. ``True`` to one caller only.

```

In `packages/postern-core/src/postern_core/auth/device_codes.py`, replace:

```python
        self._codes[device_code] = existing.__class__(
            **{**asdict_frozen(existing), "exchanged_at": datetime.now(UTC)}
        )
```

with:

```python
        self._codes[device_code] = existing.__class__(
            **{
                **asdict_frozen(existing),
                "exchanged_at": datetime.now(UTC),
                "session_id": session_id,
            }
        )
```

In `packages/postern-core/src/postern_core/auth/device_codes.py`, replace:

```python

    async def consume_device_code(self, device_code: str) -> bool:
        """Claim this code for one exchange. ``True`` to one caller only.
```

with:

```python

    async def consume_device_code(self, device_code: str, *, session_id: str) -> bool:
        """Claim this code for one exchange. ``True`` to one caller only.
```

In `packages/postern-core/src/postern_core/auth/device_codes.py`, replace:

```python
                        return False
                    spent = DeviceCode(**{**asdict_frozen(code), "exchanged_at": datetime.now(UTC)})
                    pipe.multi()
```

with:

```python
                        return False
                    spent = DeviceCode(
                        **{
                            **asdict_frozen(code),
                            "exchanged_at": datetime.now(UTC),
                            "session_id": session_id,
                        }
                    )
                    pipe.multi()
```

In `packages/postern-core/src/postern_core/auth/device_codes.py`, replace:

```python
        "scanner_ip": dc.scanner_ip,
    }
```

with:

```python
        "scanner_ip": dc.scanner_ip,
        "session_id": dc.session_id,
    }
```

In `packages/postern-core/src/postern_core/auth/device_codes.py`, replace:

```python
        scanner_ip=str(raw_scanner_ip) if raw_scanner_ip is not None else None,
    )
```

with:

```python
        scanner_ip=str(raw_scanner_ip) if raw_scanner_ip is not None else None,
        # ABSENT MEANS EMPTY: a record an earlier release wrote was exchanged,
        # if at all, before any family existed, so there is none to recall.
        session_id=str(data.get("session_id", "")),
    )
```

In `services/confirm/audit.py`, replace:

```python
#: for a customer who is not revoked, and refused to issue anything, because
#: issuance is disabled (since 2026-09-30) until the layer-1 session token
#: exists.
#:
```

with:

```python
#: for a customer who is not revoked, and refused to issue anything, because
#: issuance was disabled (on 2026-09-30) until the layer-1 session token
#: existed.
#:
#: HISTORICAL SINCE THE LAYER-1 SESSION TOKEN, and kept for the rows that
#: carry it: ``POST /token`` issues a session again and no code in this
#: repository writes this literal any more. ``audit_log`` is append-only, so
#: deleting the name would leave those rows carrying a value nothing in the
#: tree names -- the precedent ``DETAIL_USER_CODE_MISMATCH`` set.
#:
```

In `services/confirm/audit.py`, replace:

```python
    customer whose app scanned it, ``POST /approve`` pairs the client, and
    ``POST /token`` mints the read token that pairing authorises; all three
    write through this class, which is why ``tool_name`` and ``route`` are
```

with:

```python
    customer whose app scanned it, ``POST /approve`` pairs the client, and
    ``POST /token`` issues the layer-1 session that pairing authorises; all three
    write through this class, which is why ``tool_name`` and ``route`` are
```

In `services/confirm/audit.py`, replace:

```python
        "_route",
        "_started",
```

with:

```python
        "_route",
        "_session_id",
        "_started",
```

In `services/confirm/audit.py`, replace:

```python
        self._device_code_handle: str | None = None
        self._paired_client_id: str | None = None
```

with:

```python
        self._device_code_handle: str | None = None
        self._session_id: str | None = None
        self._paired_client_id: str | None = None
```

In `services/confirm/audit.py`, replace:

```python

    def names(self, *, device_code: str | None = None, paired_client_id: str | None = None) -> None:
        """Record which pairing this attempt was aimed at, as it becomes known.
```

with:

```python

    def names(
        self,
        *,
        device_code: str | None = None,
        session_id: str | None = None,
        paired_client_id: str | None = None,
    ) -> None:
        """Record which pairing this attempt was aimed at, as it becomes known.
```

In `services/confirm/audit.py`, replace:

```python
        ``/device_authorization`` rejects rather than truncates a longer one.
        """
```

with:

```python
        ``/device_authorization`` rejects rather than truncates a longer one.

        ``session_id`` is a refresh family's id, written RAW: it is in every
        access token of that family and so not a secret, and an operator
        revoking a family needs it verbatim. No token, no segment of one and
        no digest of one is ever written.
        """
```

In `services/confirm/audit.py`, replace:

```python
            self._device_code_handle = device_code_handle(device_code)
        if paired_client_id is not None:
```

with:

```python
            self._device_code_handle = device_code_handle(device_code)
        if session_id is not None:
            self._session_id = session_id
        if paired_client_id is not None:
```

In `services/confirm/audit.py`, replace:

```python

    # No caller since 2026-09-30; the pending session-token change uses it again.
    async def minted(self) -> None:
        """Record that a read token was signed for this customer.

```

with:

```python

    async def minted(self) -> None:
        """Record that a session was issued for this customer.

```

In `services/confirm/audit.py`, replace:

```python

        FOUR KEYS AT MOST, IN THIS ORDER, and the order is the first-fit rule
        ``cap_arguments`` applies: server-chosen keys first, the one
```

with:

```python

        FIVE KEYS AT MOST, IN THIS ORDER, and the order is the first-fit rule
        ``cap_arguments`` applies: server-chosen keys first, the one
```

In `services/confirm/audit.py`, replace:

```python
            tree["device_code_handle"] = self._device_code_handle
        if self._client_ip is not None:
```

with:

```python
            tree["device_code_handle"] = self._device_code_handle
        if self._session_id is not None:
            tree["session_id"] = self._session_id
        if self._client_ip is not None:
```

In `services/confirm/device_auth.py`, replace:

```python
- ``POST /token`` with ``grant_type=device_code`` — The browser's poll.
  Returns an error until the mobile app approves, and since 2026-09-30 a 503
  after it too: token issuance is disabled pending the layer-1 session token
  (see "WHAT ``/token`` RETURNS" below).
- ``POST /scan`` -- Mobile app scan of the QR (binds the pairing to the first
```

with:

```python
- ``POST /token`` with ``grant_type=device_code`` — The browser's poll.
  Returns an error until the mobile app approves, then a layer-1 session:
  an access token for this deployment's MCP server and a refresh token (see
  "WHAT ``/token`` RETURNS" below).
- ``POST /scan`` -- Mobile app scan of the QR (binds the pairing to the first
```

In `services/confirm/device_auth.py`, replace:

```python
The confirm service is the right home for these because:
1. It holds the READ key the device grant used to mint the browser's token
   (a controlled exception to the key-split architecture — see
   ``ConfirmSettings`` docstring). Nothing on this path signs with it while
   issuance is disabled; the key stays wired until the session-token change.
2. The approval callback needs to update device code state, which lives in
```

with:

```python
The confirm service is the right home for these because:
1. It holds the SESSION key, which signs the layer-1 access token and
   nothing else (``services/confirm/session_token.py``), and publishes its
   public half at ``/session/jwks.json`` for ``services/api`` to verify.
2. The approval callback needs to update device code state, which lives in
```

In `services/confirm/device_auth.py`, replace:

```python
``sub``, before the device code is touched, and ``POST /token`` on the
``customer_ref`` stored on the device code, before the issuance refusal.
Nothing is keyed on ``DeviceCode.client_id`` -- the browser supplies it
```

with:

```python
``sub``, before the device code is touched, and ``POST /token`` on the
``customer_ref`` stored on the device code, before anything is issued.
Nothing is keyed on ``DeviceCode.client_id`` -- the browser supplies it
```

In `services/confirm/device_auth.py`, replace:

```python
customer named in a JSON body. Both are gone: the identity comes from a
verified assertion, and ``/token`` returns no token at all. A write token is
minted inside the approval path in ``services/confirm/callback.py``, where it
```

with:

```python
customer named in a JSON body. Both are gone: the identity comes from a
verified assertion, and ``/token`` returns no write token. A write token is
minted inside the approval path in ``services/confirm/callback.py``, where it
```

In `services/confirm/device_auth.py`, replace:

```python

WHAT ``/token`` RETURNS, since 2026-09-30: for an approved, unexpired code
whose customer is not revoked, a 503 ``temporarily_unavailable`` ("session
token issuance is not enabled"), with the code left unspent and one
``audit_log`` row under ``DETAIL_ISSUANCE_DISABLED``. Until then it returned a
read token with ``aud=accounts.svc``, ``scope=accounts:read`` and
``act.sub=svc:postern``, signed with the READ key. That is a layer-2 backend
token, and handoff §7.1 keeps the two layers apart for this reason: under
Vault both services sign with transit key ``postern-read``, which
``services/api`` publishes at its JWKS and Istio trusts, so any client that
completed a pairing, a phishing client included, held a token the accounts
backend accepts. The browser should hold a layer-1 session token that only
this deployment's MCP server accepts. That token is a later change; until it
lands, this endpoint issues nothing.

```

with:

```python

WHAT ``/token`` RETURNS: for an approved, unexpired code whose customer is
not revoked, a layer-1 access token (``aud`` = the MCP server, 600 seconds,
signed with the SESSION key) and a ``prt1.`` refresh token, the code spent in
the same compare-and-set that records the family. Before 30 September 2026 it
returned a read token with ``aud=accounts.svc``, ``scope=accounts:read`` and
``act.sub=svc:postern``, signed with the READ key: a layer-2 backend token,
which handoff §7.1 keeps apart from layer 1 because under Vault both services
signed with transit key ``postern-read`` and any client that completed a
pairing held a token the accounts backend accepts. From then until the
session token landed it answered 503 and issued nothing
(``DETAIL_ISSUANCE_DISABLED``, historical now). ``dev-docs/device-grant-session-token-spec.md``
is the contract.

```

In `services/confirm/device_auth.py`, replace:

```python
    store = build_device_code_store(settings)
    routes = device_auth_routes(
        store=store,
        settings=settings,
        read_minter=read_minter,
    )
"""
```

with:

```python
    store = build_device_code_store(settings)
    routes = device_auth_routes(store=store, settings=settings)
"""
```

In `services/confirm/device_auth.py`, replace:

```python
)
from postern_core.auth.internal_jwt import InternalTokenMinter
from postern_core.auth.revocation import RevocationStoreUnavailable
```

with:

```python
)
from postern_core.auth.refresh_sessions import (
    RefreshSession,
    RefreshSessionStoreBase,
    RefreshSessionStoreFull,
    canonical_scope,
    hash_refresh_token,
    ms_of,
    new_refresh_token,
    new_sid,
)
from postern_core.auth.resource_uri import normalize_resource
from postern_core.auth.revocation import RevocationStoreUnavailable
```

In `services/confirm/device_auth.py`, replace:

```python
    DETAIL_INVALID_SUBJECT,
    DETAIL_ISSUANCE_DISABLED,
    DETAIL_NOT_SCANNED,
```

with:

```python
    DETAIL_INVALID_SUBJECT,
    DETAIL_NOT_SCANNED,
```

In `services/confirm/device_auth.py`, replace:

```python
    customer_revoked,
    log_refusal,
```

with:

```python
    customer_revoked,
    customer_revoked_since,
    log_refusal,
```

In `services/confirm/device_auth.py`, replace:

```python
    store_unavailable_response,
)
```

with:

```python
    store_unavailable_response,
)
from services.confirm.session_token import (
    ACCESS_TOKEN_LIFETIME_SECONDS,
    SessionTokenMinter,
)
```

In `services/confirm/device_auth.py`, replace:

```python
PAIRING_ENRICHMENT_SLOTS = 8

```

with:

```python
PAIRING_ENRICHMENT_SLOTS = 8

#: The ``client_id`` a pairing may not declare. ``services/api``'s risk
#: middleware uses ``-`` for "no client on this token", so a pairing named
#: ``-`` would share one risk budget and one revocation key with every token
#: that carries none. Spelled here rather than imported, because
#: ``.importlinter`` forbids this service from reading ``services.api``.
RESERVED_CLIENT_ID = "-"

#: RFC 6749 section 5.1: "The authorization server MUST include the HTTP
#: "Cache-Control" response header field [RFC2616] with a value of "no-store"
#: in any response containing tokens ... as well as the "Pragma" response
#: header field [RFC2616] with a value of "no-cache"." On every ``/token``
#: response, not only the ones that carry a token.
TOKEN_RESPONSE_HEADERS = {"Cache-Control": "no-store", "Pragma": "no-cache"}

#: How far this process's clock may disagree with Redis's when an approval
#: (written on this clock) is compared with a customer revocation stamp
#: (written on Redis's), in milliseconds. It errs toward refusal: a customer
#: whose approval lands within two seconds after a revocation re-pairs.
APPROVAL_CLOCK_TOLERANCE_MS = 2_000

```

In `services/confirm/device_auth.py`, replace:

```python
        return _error(400, "invalid_request", "client_id is required")

```

with:

```python
        return _error(400, "invalid_request", "client_id is required")
    if client_id == RESERVED_CLIENT_ID:
        return _error(400, "invalid_request", "client_id '-' is reserved")

```

In `services/confirm/device_auth.py`, replace:

```python
async def token_endpoint(request: Request) -> JSONResponse:
    """Answer a device-code poll, and record every answer that names a customer.

    ISSUANCE IS DISABLED SINCE 2026-09-30, pending the layer-1 session token.
    An approved, unexpired code for a customer who is not revoked is answered
    503 ``temporarily_unavailable`` with ``error_description`` "session token
    issuance is not enabled"; nothing is minted, the code is NOT spent, and
    the row carries ``DETAIL_ISSUANCE_DISABLED``. Until then this endpoint
    returned a read token: ``aud=accounts.svc``, ``scope=accounts:read``,
    ``act.sub=svc:postern``, 60 seconds, signed with the READ key. That is a
    layer-2 backend token (handoff §7.1). Under Vault both services sign with
    transit key ``postern-read``, which ``services/api`` publishes at its JWKS
    and Istio trusts, so any client that completed a pairing, a phishing
    client included, held a token the accounts backend accepts. The browser
    should hold a layer-1 token only this deployment's MCP server accepts; it
    does not exist yet, so nothing is issued. The single-use argument below is
    kept because it applies unchanged to whatever the session-token change
    issues here, and ``dev-docs/decisions/0012-device-code-single-use.md``
    still carries it; no exit spends a code today.

```

with:

```python
async def token_endpoint(request: Request) -> JSONResponse:
    """``POST /token``, every answer carrying ``TOKEN_RESPONSE_HEADERS``.

    A wrapper so no exit can forget the two headers RFC 6749 section 5.1
    requires: `_token_response` answers, this stamps.
    """
    response = await _token_response(request)
    response.headers.update(TOKEN_RESPONSE_HEADERS)
    return response


def _resource_refusal(form: Any, settings: ConfirmSettings) -> JSONResponse | None:
    """400 ``invalid_target`` for a ``resource`` this deployment does not serve.

    RFC 8707 section 2. Absent is accepted. Present, it must occur once and,
    in `postern_core.auth.resource_uri`'s normal form, equal the access
    token's audience; a fragment, a relative reference and a repeat are all
    ``invalid_target`` ("The requested resource is invalid, missing, unknown,
    or malformed"). Request shape only, so no row.
    """
    values = form.getlist("resource")
    if not values:
        return None
    presented = values[0] if len(values) == 1 and isinstance(values[0], str) else None
    normalized = normalize_resource(presented) if presented is not None else None
    if normalized is None or normalized != settings.session_token_audience:
        return _error(400, "invalid_target", "the requested resource is not served here")
    return None


async def _token_response(request: Request) -> JSONResponse:
    """Answer a device-code poll, and record every answer that names a customer.

    AN APPROVED CODE IS WORTH ONE SESSION. An approved, unexpired, unspent
    code for a customer who is not revoked gets a layer-1 access token and a
    refresh token (spec section 5 of
    ``dev-docs/device-grant-session-token-spec.md``), and the code is spent in
    the same compare-and-set that records which family it created. Before
    30 September 2026 this endpoint returned a layer-2 read token
    (``aud=accounts.svc``), and between then and the session token it issued
    nothing (``DETAIL_ISSUANCE_DISABLED``).

```

In `services/confirm/device_auth.py`, replace:

```python
        device_code: The opaque device code from /device_authorization.

```

with:

```python
        device_code: The opaque device code from /device_authorization.
        resource: Optional, RFC 8707; see `_resource_refusal`.

```

In `services/confirm/device_auth.py`, replace:

```python

    Response after approval (503), since 2026-09-30:
        {
            "error": "temporarily_unavailable",
            "error_description": "session token issuance is not enabled",
        }

    There is no token in that response, and there must never again be one a
    backend accepts: not a ``write_token`` (audit finding C-01) and not the
    read token this endpoint returned until 2026-09-30. This endpoint is
    public and its only credential is the ``device_code``, so anything it
    returns is reachable by whoever holds that value. The write path mints its
    own token inside ``services/confirm/callback.py``, per request, and never
    hands one out.

```

with:

```python

    Response after approval (200):
        {"access_token": "...", "token_type": "Bearer", "expires_in": 600,
         "refresh_token": "prt1.<sid>.<secret>", "scope": "<canonical scopes>"}

    There is no layer-2 token in that response and there must never be one: not
    a ``write_token`` (audit finding C-01) and not the read token this
    endpoint returned until 2026-09-30. The access token's audience is this
    deployment's MCP server and its key signs nothing else, so no domain
    service accepts it. The write path mints its own token inside
    ``services/confirm/callback.py``, per request, and never hands one out.

```

In `services/confirm/device_auth.py`, replace:

```python
            2026-09-30 also answered to an approved, unspent code polled
            within the interval, because such a poll gets a retryable 503.
        access_denied — user explicitly denied on mobile app, OR the customer
```

with:

```python
            2026-09-30 also answered to an approved, unspent code polled
            within the interval, because two retryable 503s remain: the
            revocation store's outage and a full refresh-family store.
        access_denied — user explicitly denied on mobile app, OR the customer
```

In `services/confirm/device_auth.py`, replace:

```python

    And two that are RFC 6749 §5.2's, because RFC 8628 has no code for either:
        invalid_grant — the code is unknown, or a build before 2026-09-30
            spent it. One body for both, so the response is not an oracle;
            ``_unredeemable_response`` above carries why this code and not one
            of the four.
        temporarily_unavailable — either the revocation store could not be
            consulted, or the code is approved and issuance is disabled. Both
            answer 503 and spend nothing; the two descriptions differ.

```

with:

```python

    And three that are RFC 6749 §5.2's or RFC 8707's, because RFC 8628 has
    no code for them:
        invalid_grant -- the code is unknown, or spent (by an earlier exchange,
            or by a concurrent one that won the claim). One body for all
            three, so the response is not an oracle; ``_unredeemable_response``
            above carries why this code and not one of the four.
        temporarily_unavailable -- the revocation store could not be
            consulted, or the refresh-family store is full. Both answer 503
            with ``Retry-After`` set to the poll interval and spend nothing.
        invalid_target -- a ``resource`` this deployment does not serve.

```

In `services/confirm/device_auth.py`, replace:

```python
    ``audit_log`` row until 2026-09-26, which left the device grant's chain
    with a hole in the middle. It now writes exactly one row on each of FIVE
    exits -- the issuance-disabled refusal, a ZT-7 refusal, a stored identity
    that will not parse, a revocation store that could not answer, and a spent
    code -- plus one for any exception ``_exchange`` raises, and nothing on
    the other eight: a wrong grant type, a missing ``device_code``, an unknown
    code, an expired code, ``slow_down`` on a pending code, ``slow_down`` on
    an approved one, ``authorization_pending``, and an approved code with no
    customer on it.

    RE-COUNTED ON 2026-09-30, twice, from the exits of this function,
    ``_paced`` and ``_exchange`` together, which is the only way to count
    them. The count was six recorded and seven unrecorded before the
    issuance refusal: the mint went, the refusal took its place, and the
    second spent-code exit (a lost ``consume_device_code`` claim) went with
    the claim, leaving five and seven. Pacing approved codes then added the
    eighth unrecorded exit.

```

with:

```python
    ``audit_log`` row until 2026-09-26, which left the device grant's chain
    with a hole in the middle. It now writes exactly one row on each of SIX
    exits -- the mint, a ZT-7 refusal (now, or since the approval), a stored
    identity that will not parse, a revocation store that could not answer, a
    full refresh-family store, and a spent code (a replay, or a lost claim)
    -- plus one for any exception ``_exchange`` raises, and nothing on the
    other nine: a wrong grant type, an unserved ``resource``, a missing
    ``device_code``, an unknown code, an expired code, ``slow_down`` on a
    pending code, ``slow_down`` on an approved one, ``authorization_pending``,
    and an approved code with no customer on it.

    RE-COUNTED WITH THE LAYER-1 SESSION TOKEN, from the exits of this
    function, ``_paced``, `_resource_refusal` and ``_exchange`` together,
    which is the only way to count them. The issuance refusal went and the
    mint came back; the full family store and the lost claim are new
    recorded exits (the lost claim under the spent-code detail it shares);
    the ``resource`` refusal is a new unrecorded one. Six recorded, nine not.

```

In `services/confirm/device_auth.py`, replace:

```python
    and 900-second lifetime a poll loop can run 180 times and write nothing
    while pending, and at most one ``issuance_disabled`` row per interval once
    approved. The empty-``customer_ref`` exit is the one that reads the field
    and finds nobody, and it is logged instead.

    NOTHING OF A TOKEN WOULD GO ANYWHERE, and the rule stands for the
    session-token change: not the string, not a segment of it, not a digest.
    """
```

with:

```python
    and 900-second lifetime a poll loop can run 180 times and write nothing
    while pending, and at most one row per interval once approved while a
    503 is being retried. The empty-``customer_ref`` exit is the one that
    reads the field and finds nobody, and it is logged instead.

    NOTHING OF A TOKEN GOES INTO A ROW: not the string, not a segment of it,
    not a digest. The row carries the family's ``session_id``, which every
    access token of the family carries anyway.
    """
```

In `services/confirm/device_auth.py`, replace:

```python

    code: DeviceCode | None = await store.get_device_code(device_code_value)
```

with:

```python

    # AHEAD OF THE LOOKUP: request shape only, so it resolves nobody and
    # writes no row.
    unserved = _resource_refusal(form, settings)
    if unserved is not None:
        return unserved

    code: DeviceCode | None = await store.get_device_code(device_code_value)
```

In `services/confirm/device_auth.py`, replace:

```python
    #
    # WHY APPROVED CODES ARE PACED NOW. They used to be exempt because an
    # approved poll got its token at once. While issuance is disabled an
    # approved poll gets a retryable 503 instead, and a client honouring it
    # would retry at the address-bucket limiter's pace (300 a minute) until
    # the 900-second TTL, each retry costing an ``audit_log`` INSERT and a
    # revocation read. Paced, it costs one of each per interval.
    #
```

with:

```python
    #
    # WHY APPROVED CODES ARE PACED. The first poll after approval is answered
    # at once (its own map, never paced by the last pending poll) and on
    # success spends the code. What the pacing governs is an approved code
    # that gets a RETRYABLE answer -- the revocation store's outage 503 and a
    # full refresh-family store's 503 -- which a client honouring it would
    # otherwise retry at the address-bucket limiter's pace (300 a minute),
    # each retry costing an ``audit_log`` INSERT and a store read. Paced, it
    # costs one of each per interval. It also cuts a burst of concurrent polls
    # on one approved code within one process to one, before a family is
    # drawn, so orphaned families come only from polls on different replicas.
    #
```

In `services/confirm/device_auth.py`, replace:

```python

    # Approved. Nothing is minted below: issuance is disabled pending the
    # layer-1 session token (`_exchange`'s last return says why).
    #
```

with:

```python

    # Approved.
    #
```

In `services/confirm/device_auth.py`, replace:

```python
    # THE ROW IS COMMITTED BEFORE THE RESPONSE IS RETURNED, fail-closed per
    # decision 0006: a raise here drops `response` and the caller gets a 500.
    # Every exit refuses since 2026-09-30, so there is no mint for this to
    # guard; the order is kept because the session-token change will mint
    # here again, and `PairingAudit`'s "FAIL CLOSED AT A MINT" section carries
    # why that order is the right one. Do not move this below the `return`.
    try:
        await audit.refused(detail)
    except Exception as audit_exc:
```

with:

```python
    # THE ROW IS COMMITTED BEFORE THE RESPONSE IS RETURNED, fail-closed per
    # decision 0006: a raise here drops `response` and the caller gets a 500,
    # so a session no row names never leaves this process. `PairingAudit`'s
    # "FAIL CLOSED AT A MINT" section carries why that order is the right one.
    # Do not move this below the `return`.
    try:
        if detail is None:
            await audit.minted()
        else:
            await audit.refused(detail)
    except Exception as audit_exc:
```

In `services/confirm/device_auth.py`, replace:

```python
    code: DeviceCode,
) -> tuple[JSONResponse, str]:
    """The spent check, the ZT-7 check and the refusal, returning ``(response, detail)``.

    ``detail`` is always one of ``services/confirm/audit.py``'s ``DETAIL_*``
    literals or an exception's type name, because since 2026-09-30 no exit
    here mints: an approved code that passes every check is answered with
    ``DETAIL_ISSUANCE_DISABLED`` (the comment at that return carries why).
    Split out from ``token_endpoint`` so the row is written in exactly one
    place, which is the same division ``approve_callback`` and
    ``services/confirm/callback.py`` both make.

```

with:

```python
    code: DeviceCode,
) -> tuple[JSONResponse, str | None]:
    """The checks and the mint, returning ``(response, detail)``.

    ``detail`` is ``None`` for the one exit that issues a session, and
    otherwise one of ``services/confirm/audit.py``'s ``DETAIL_*`` literals or
    an exception's type name. Split out from ``token_endpoint`` so the row is
    written in exactly one place, which is the same division
    ``approve_callback`` and ``services/confirm/callback.py`` both make.

```

In `services/confirm/device_auth.py`, replace:

```python
    503 ``temporarily_unavailable``, which tells the browser to come back for a
    grant no retry will ever redeem. No build from 2026-09-30 on spends a
    code, so this check answers only codes an earlier build spent while they
    live in a shared store.

    THE ZT-7 CHECK COMES BEFORE THE ISSUANCE REFUSAL, so a revoked customer is
    still answered ``access_denied`` and recorded under ``DETAIL_REVOKED``, as
    they were when this endpoint minted.
    """
```

with:

```python
    503 ``temporarily_unavailable``, which tells the browser to come back for a
    grant no retry will ever redeem.

    THEN ZT-7, THEN THE MINT, in spec section 5's order: a customer revoked
    now, or revoked at or after the approval (step 0, which a restore does not
    undo); then the family is drawn and created BEFORE the code is spent, so a
    recall at ``POST /scan`` that sees the code exchanged always finds the
    family and its first ``jti``; then the claim; then the signature.
    """
```

In `services/confirm/device_auth.py`, replace:

```python
    # from a refusal -- the caller cannot, and must not.
    try:
        revoked = await customer_revoked(request, customer.value)
    except RevocationStoreUnavailable as exc:
        logger.warning("device grant: revocation store unavailable, refusing to mint")
        return store_unavailable_response(), type(exc).__name__
    if revoked:
        log_refusal("a device-grant token exchange")
```

with:

```python
    # from a refusal -- the caller cannot, and must not.
    settings: ConfirmSettings = request.app.state.settings
    retry_after = settings.device_poll_interval_seconds
    try:
        revoked = await customer_revoked(request, customer.value)
        # STEP 0: REVOKED SINCE THE APPROVAL. The approval predates a
        # revocation, so a later restore must not make it redeemable. The one
        # comparison across two clocks -- the approval is this process's, the
        # stamp Redis's -- so it carries `APPROVAL_CLOCK_TOLERANCE_MS` and
        # errs toward refusal.
        stamp = await customer_revoked_since(request, customer.value)
    except RevocationStoreUnavailable as exc:
        logger.warning("device grant: revocation store unavailable, refusing to mint")
        return store_unavailable_response(retry_after), type(exc).__name__
    approved_ms = ms_of(code.approved_at) if code.approved_at is not None else 0
    if revoked or (stamp is not None and stamp >= approved_ms - APPROVAL_CLOCK_TOLERANCE_MS):
        log_refusal("a device-grant token exchange")
```

In `services/confirm/device_auth.py`, replace:

```python

    # ISSUANCE IS DISABLED, AND NOTHING IS SPENT OR SIGNED. Until 2026-09-30
    # this point claimed the code with ``consume_device_code`` and minted a
    # token with ``aud=accounts.svc``, ``scope=accounts:read`` and
    # ``act.sub=svc:postern``, signed with the READ key, and returned it to
    # the browser. That is a layer-2 backend token (handoff §7.1): under Vault
    # both services sign with the same transit key, ``services/api`` publishes
    # it at its JWKS and Istio trusts that set, so any client that completed a
    # pairing, a phishing client included, held a credential the accounts
    # backend accepts. What the browser should get is a layer-1 session token
    # only this deployment's own MCP server accepts, and that token does not
    # exist yet, so this endpoint issues nothing until it does.
    #
    # THE CODE IS NOT CLAIMED, because nothing is issued for it: spending it
    # would make the eventual session-token change unable to serve a pairing
    # completed today, and would turn this refusal into the spent-code one
    # on the next poll. The spent check above still answers any code a build
    # before this one spent.
    #
    # AFTER THE ZT-7 CHECK, deliberately, so a revoked customer's code is
    # still answered ``access_denied`` and a revocation-store outage still
    # answers its own 503: both are conclusions about the customer, and the
    # browser must not be able to tell from this refusal which one applies.
    #
    # 503 ``temporarily_unavailable`` rather than a terminal code, for the
    # reason `services/confirm/revocation.py`'s ``store_unavailable_response``
    # gives: the browser did nothing wrong, and ``access_denied`` would tell it
    # the customer refused a pairing they in fact approved. The read minter is
    # still wired on ``app.state``; removing it belongs to the session-token
    # change.
    #
    # ``Retry-After`` carries the poll interval, which is also what
    # ``token_endpoint`` now paces approved codes at: a client that honours
    # the header is never answered ``slow_down``.
    settings: ConfirmSettings = request.app.state.settings
    return (
        JSONResponse(
            status_code=503,
            content={
                "error": "temporarily_unavailable",
                "error_description": "session token issuance is not enabled",
            },
            headers={"Retry-After": str(settings.device_poll_interval_seconds)},
        ),
        DETAIL_ISSUANCE_DISABLED,
    )
```

with:

```python

    # STEP 1: DRAW the family id, the first refresh token and the access
    # token's claims. The `jti` is drawn here, before anything is written, so
    # the family can name it from its first moment.
    minter: SessionTokenMinter = request.app.state.session_minter
    sessions: RefreshSessionStoreBase = request.app.state.refresh_session_store
    sid = new_sid()
    refresh_token = new_refresh_token(sid)
    scope = canonical_scope(code.scopes)
    claims = minter.prepare(customer=customer, client_id=code.client_id, scope=scope, sid=sid)
    audit.names(session_id=sid)

    # STEP 2: CREATE THE FAMILY BEFORE THE CODE IS SPENT. A full store leaves
    # the code redeemable and answers a retryable 503, the argument this
    # docstring makes for ZT-7 before the claim.
    now = datetime.now(UTC)
    family = RefreshSession(
        sid=sid,
        customer_ref=customer.value,
        client_id=code.client_id,
        scopes=scope,
        created_at=now,
        expires_at=now,
        generation=0,
        current_hash=hash_refresh_token(refresh_token),
        access_tokens=((claims.jti, datetime.fromtimestamp(claims.exp, UTC)),),
        device_code_handle=device_code_handle(code.device_code),
    )
    try:
        await sessions.create(family)
    except RefreshSessionStoreFull as exc:
        logger.warning("device grant: %s; refusing to mint", exc)
        return _session_store_full_response(retry_after), type(exc).__name__

    # STEP 3: SPEND THE CODE, recording which family it created. A lost claim
    # means a concurrent exchange won: this family is an orphan nobody holds a
    # token for, so it is discarded, and a failure to discard is tolerated --
    # the orphan holds a hash nobody has and expires within the hour.
    store: DeviceCodeStoreBase = request.app.state.device_code_store
    if not await store.consume_device_code(code.device_code, session_id=sid):
        try:
            await sessions.discard(sid)
        except Exception as exc:  # noqa: BLE001 -- an orphan is harmless, the claim is not
            logger.warning(
                "device grant: could not discard orphaned session family %s after a lost claim: %s",
                sid,
                type(exc).__name__,
            )
        return _unredeemable_response(), DETAIL_DEVICE_CODE_SPENT

    # STEP 4: SIGN. A raise leaves the code spent and a family holding a
    # never-issued `jti`; harmless, and the customer re-pairs.
    access_token = minter.sign(claims)
    return (
        JSONResponse(
            status_code=200,
            content={
                "access_token": access_token,
                "token_type": "Bearer",
                "expires_in": ACCESS_TOKEN_LIFETIME_SECONDS,
                "refresh_token": refresh_token,
                "scope": scope,
            },
        ),
        None,
    )


def _session_store_full_response(retry_after: int) -> JSONResponse:
    """The 503 ``POST /token`` answers when the refresh-family store is full.

    The shape of `_store_full_response`, with ``Retry-After`` set to the poll
    interval rather than the device-code lifetime: the code is live, paced,
    and redeemable the moment a family expires.
    """
    return JSONResponse(
        status_code=503,
        content={
            "error": "temporarily_unavailable",
            "error_description": "the service cannot open a new session right now; retry shortly",
        },
        headers={"Retry-After": str(retry_after)},
    )
```

> **Amended 1 October 2026 (review follow-up, commit after Task 6).** The tree differs from this block in four places. (a) ``audit.names(session_id=sid)`` runs after ``create`` succeeds, so a refused row never names a family that was never stored. (b) ``create`` raising ``RedisError``, ``OSError`` or ``TimeoutError`` answers the same retryable 503 as a full store, under the exception's class name. (c) ``consume_device_code`` raising discards the family, then re-raises. (d) The 503 helper is ``_session_store_unavailable_response``, and discarding goes through ``_discard_orphan``. Separately, ``TokenResponseHeaders`` (pure ASGI, in ``services/confirm/device_auth.py``) is wrapped around the whole app by a ``Starlette`` subclass in ``services/confirm/main.py``, outside ``ServerErrorMiddleware``, so every ``/token`` response carries both headers. ``DETAIL_DEVICE_CODE_SPENT``'s comment and ``docs/user-guide/components/audit.md`` say how a lost claim's row differs from a replay's.

In `services/confirm/device_auth.py`, replace:

```python
# verification. It marks the device code approved so the browser's poll at
# ``POST /token`` stops answering ``authorization_pending`` (it answers the
# issuance-disabled 503 instead, until the session-token change).
#
```

with:

```python
# verification. It marks the device code approved so the browser's poll at
# ``POST /token`` stops answering ``authorization_pending`` and is issued a
# session instead.
#
```

In `services/confirm/device_auth.py`, replace:

```python
        # would be fail-closed in the response and fail-open in substance:
        # the browser polls `/token` against an approval no row names (and,
        # once the session-token change lands, is handed a token for it).
        # `PairingAudit` carries the full argument and what the availability
```

with:

```python
        # would be fail-closed in the response and fail-open in substance:
        # the browser polls `/token` against an approval no row names and is
        # handed a session for it.
        # `PairingAudit` carries the full argument and what the availability
```

In `services/confirm/device_auth.py`, replace:

```python
    settings: ConfirmSettings,
    read_minter: InternalTokenMinter,
) -> list[Route]:
```

with:

```python
    settings: ConfirmSettings,
) -> list[Route]:
```

In `services/confirm/device_auth.py`, replace:

```python
        settings: Service settings (TTL, URIs, poll interval).
        read_minter: Minter for read tokens. Accepted and not called since
            2026-09-30, while ``/token`` issuance is disabled; its removal
            belongs to the layer-1 session-token change.

```

with:

```python
        settings: Service settings (TTL, URIs, poll interval).

    NO MINTER AND NO FAMILY STORE. The handlers read the session minter and
    the refresh-family store from ``app.state``, where ``create_confirm_app``
    puts them, as they read the device code store; a parameter nothing reads
    would only look like wiring. The read minter this took until the layer-1
    session token went the same way.

```

In `services/confirm/main.py`, replace:

```python
from postern_core.auth.keys import choose_key_source
from postern_core.auth.revocation import create_revocation_store
```

with:

```python
from postern_core.auth.keys import choose_key_source
from postern_core.auth.refresh_sessions import create_refresh_session_store
from postern_core.auth.revocation import create_revocation_store
```

In `services/confirm/main.py`, replace:

```python

    # --- ZT-7 revocation (shared with every `services/api` replica) ---
```

with:

```python

    # --- Refresh families (the layer-1 session) ---
    #
    # The same ``POSTERN_REDIS_URL`` as the device code store, so a refresh on
    # any replica finds the family an exchange on any other created.
    # `_refuse_process_local_sessions` above is why this cannot silently be
    # per process.
    refresh_session_store = create_refresh_session_store(max_sessions=settings.max_refresh_sessions)

    # --- ZT-7 revocation (shared with every `services/api` replica) ---
```

In `services/confirm/main.py`, replace:

```python
        [jwks_route(write_key_source), session_jwks_route(session_key_source)]
        + device_auth_routes(
            store=device_code_store,
            settings=settings,
            read_minter=read_minter,
        )
        + verify_page_routes()
```

with:

```python
        [jwks_route(write_key_source), session_jwks_route(session_key_source)]
        + device_auth_routes(store=device_code_store, settings=settings)
        + verify_page_routes()
```

In `services/confirm/main.py`, replace:

```python
    app.state.device_code_store = device_code_store
    # Expose database for the approval callback.
```

with:

```python
    app.state.device_code_store = device_code_store
    app.state.refresh_session_store = refresh_session_store
    # Expose database for the approval callback.
```

In `services/confirm/revocation.py`, replace:

```python

def revoked_response(description: str) -> JSONResponse:
```

with:

```python

async def customer_revoked_since(request: Request, customer_ref: str) -> int | None:
    """When a revocation last named this customer, in ms, or ``None``.

    The stamp `postern_core.auth.revocation`'s ``customer_revoked_at``
    keeps after a restore. Raises ``RevocationStoreUnavailable`` like
    `customer_revoked`.
    """
    return await revocation_store(request).customer_revoked_at(customer_ref)


def revoked_response(description: str) -> JSONResponse:
```

In `services/confirm/revocation.py`, replace:

```python

def store_unavailable_response() -> JSONResponse:
    """The 503 ``POST /token`` answers when the revocation store cannot answer.
```

with:

```python

def store_unavailable_response(retry_after: int | None = None) -> JSONResponse:
    """The 503 ``POST /token`` answers when the revocation store cannot answer.
```

In `services/confirm/revocation.py`, replace:

```python
    reads the status rather than the body also sees "retry".
    """
```

with:

```python
    reads the status rather than the body also sees "retry".

    ``retry_after`` sets ``Retry-After``. ``POST /token`` passes its poll
    interval, the pace it holds an approved code's polls to, so a client that
    honours the header is never answered ``slow_down``.
    """
```

In `services/confirm/revocation.py`, replace:

```python
        },
    )
```

with:

```python
        },
        headers={"Retry-After": str(retry_after)} if retry_after is not None else None,
    )
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `uv run pytest tests/test_confirm_rate_limit.py tests/test_device_code_pairing_store.py tests/test_device_code_scanner_ip.py tests/test_device_grant.py tests/test_pairing_audit.py tests/test_qr_pairing_end_to_end.py tests/test_redis_backed_stores.py tests/test_scan.py tests/test_scan_network_signal.py tests/test_token_session_issuance.py tests/test_zt7_confirm_revocation.py -q`

Expected: 539 passed

- [ ] **Step 5: Format, then run the gate**

Run: `uv run ruff format packages services tests && make ci`

Expected: exit 0 (3681 passed at validation).

- [ ] **Step 6: Commit**

```bash
git add dev-docs/device-grant-session-token-spec.md packages/postern-core/src/postern_core/auth/device_codes.py services/confirm/audit.py services/confirm/device_auth.py services/confirm/main.py services/confirm/revocation.py tests/device_grant_helpers.py tests/test_confirm_rate_limit.py tests/test_device_code_pairing_store.py tests/test_device_code_scanner_ip.py tests/test_device_grant.py tests/test_pairing_audit.py tests/test_qr_pairing_end_to_end.py tests/test_redis_backed_stores.py tests/test_scan.py tests/test_scan_network_signal.py tests/test_token_session_issuance.py tests/test_zt7_confirm_revocation.py
git commit -m "feat(confirm): issue a layer-1 session at POST /token" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 7: The `refresh_token` grant

Spec section 6: shape checks and the lookup write nothing; the proof of possession comes before any row (an unknown hash under a real family id is `invalid_grant`, no row, and one rate-limited log line); then every exit writes one `device_grant.refresh` row. Classification, scope, the four ZT-7 checks (the last one revoking a family issued before a customer revocation), the draw, one compare-and-set rotation, and the signature, in the spec's order.

**Files:**
- Modify: `services/confirm/audit.py` (`REFRESH_TOOL_NAME` and seven `DETAIL_*` literals)
- Modify: `services/confirm/device_auth.py` (`UNKNOWN_REFRESH_LOG_INTERVAL_SECONDS`, `UNKNOWN_REFRESH_LOG_ENTRIES`, the grant dispatch, `_form_value`, `_unrefreshable_response`, `_log_unknown_refresh`, `_reassert`, `_refresh_grant`, `_refresh`, `_refresh_revoked`, `_answer_revoked`, `_answer_reuse`, `_reuse_detected`)
- Create: `tests/test_refresh_grant.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/test_refresh_grant.py` with:

```python
"""``POST /token`` with ``grant_type=refresh_token`` (spec section 6).

Every branch, through the assembled confirm app: the shape checks and the
lookup that write nothing; the proof of possession, before which nothing is
recorded and after which every exit writes one ``device_grant.refresh`` row;
reuse detection, revocation re-assertion and its convergence; the generation
and lifetime limits; the ``client_id`` transplant signal; scope
canonicalization and narrowing; and the four ZT-7 checks, including a family
issued before a since-restored customer revocation.
"""

from __future__ import annotations

import base64
import dataclasses
import json
import logging
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx2
import pytest
from fastmcp.server.auth.providers.jwt import RSAKeyPair
from postern_core.auth.refresh_sessions import (
    MAX_GENERATIONS,
    InMemoryRefreshSessionStore,
    RefreshSession,
    RefreshSessionStoreContended,
    new_refresh_token,
)
from postern_core.auth.revocation import InMemoryRevocationStore, RevocationStoreUnavailable
from postern_core.store.engine import Database
from postern_core.store.models import OUTCOME_RAISED, OUTCOME_RETURNED, AuditEntry
from sqlalchemy import select
from starlette.applications import Starlette

from services.confirm.audit import (
    DETAIL_CLIENT_ID_MISMATCH,
    DETAIL_ISSUED_BEFORE_REVOCATION,
    DETAIL_REFRESH_REUSED,
    DETAIL_REVOKED,
    DETAIL_SCOPE_EXCEEDED,
    DETAIL_SESSION_EXPIRED,
    DETAIL_SESSION_GENERATIONS_EXHAUSTED,
    DETAIL_SESSION_REVOKED,
    REFRESH_TOOL_NAME,
    TOKEN_ROUTE,
)
from tests.device_grant_helpers import session_claims
from tests.fixtures.append_only_bypass import (
    delete_audit_rows_by_bypassing_the_append_only_triggers,
)
from tests.test_token_session_issuance import CUSTOMER, RESOURCE, _app, _approved, _exchange

SCOPES = "accounts:read cards:read transactions:read"


@pytest.fixture(scope="module")
def key_pair() -> RSAKeyPair:
    return RSAKeyPair.generate()


@pytest.fixture()
async def clean(database: Database) -> AsyncIterator[Database]:
    async with database.sessionmaker() as s:
        await delete_audit_rows_by_bypassing_the_append_only_triggers(s)
        await s.commit()
    yield database


@pytest.fixture()
def app(key_pair: RSAKeyPair, pg_url: str) -> Starlette:
    return _app(key_pair, pg_url)


async def _session(app: Starlette, key_pair: RSAKeyPair) -> dict[str, Any]:
    """A pairing exchanged for a session; the parsed 200 body."""
    device = await _approved(app, key_pair, scopes=SCOPES)
    response = await _exchange(app, device["device_code"])
    session_claims(response, app)
    body: dict[str, Any] = response.json()
    return body


async def _refresh(app: Starlette, refresh_token: str | None, **extra: str) -> httpx2.Response:
    data = {"grant_type": "refresh_token", **extra}
    if refresh_token is not None:
        data["refresh_token"] = refresh_token
    async with httpx2.AsyncClient(
        transport=httpx2.ASGITransport(app=app, raise_app_exceptions=False),
        base_url="http://t",
    ) as client:
        return await client.post("/token", data=data)


async def _rows(db: Database) -> list[AuditEntry]:
    async with db.sessionmaker() as s:
        result = await s.execute(
            select(AuditEntry)
            .where(AuditEntry.tool_name == REFRESH_TOOL_NAME)
            .order_by(AuditEntry.id)
        )
        return list(result.scalars())


def _sid(body: dict[str, Any]) -> str:
    return str(body["refresh_token"].split(".")[1])


def _jti(body: dict[str, Any]) -> str:
    """The ``jti`` of the access token in a session body, read without verifying."""
    payload = body["access_token"].split(".")[1]
    return str(json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))["jti"])


async def _family(app: Starlette, body: dict[str, Any]) -> RefreshSession:
    sessions: InMemoryRefreshSessionStore = app.state.refresh_session_store
    return sessions._sessions[_sid(body)]


def _refused(response: httpx2.Response) -> None:
    assert response.status_code == 400, response.text
    assert response.json() == {
        "error": "invalid_grant",
        "error_description": "refresh token cannot be redeemed",
    }


class TestARefreshThatSucceeds:
    async def test_it_rotates_and_issues_a_fresh_access_token_in_the_same_family(
        self, app: Starlette, key_pair: RSAKeyPair, clean: Database
    ) -> None:
        first = await _session(app, key_pair)
        response = await _refresh(app, first["refresh_token"])
        claims = session_claims(response, app)
        body = response.json()
        assert body["refresh_token"] != first["refresh_token"]
        assert _sid(body) == _sid(first)
        assert claims["sid"] == _sid(first)
        assert claims["scope"] == SCOPES
        family = await _family(app, body)
        assert family.generation == 1
        assert len(family.access_tokens) == 2

        (row,) = await _rows(clean)
        assert (row.outcome, row.detail) == (OUTCOME_RETURNED, None)
        assert row.customer_ref == CUSTOMER
        assert row.arguments["route"] == TOKEN_ROUTE
        assert row.arguments["session_id"] == _sid(first)
        assert row.arguments["paired_client_id"] == "claude-code"
        assert "device_code_handle" not in row.arguments
        for token in (first["refresh_token"], body["refresh_token"], body["access_token"]):
            assert token not in str(row.arguments)

    async def test_a_matching_client_id_and_resource_are_accepted(
        self, app: Starlette, key_pair: RSAKeyPair, clean: Database
    ) -> None:
        first = await _session(app, key_pair)
        response = await _refresh(
            app, first["refresh_token"], client_id="claude-code", resource=RESOURCE
        )
        session_claims(response, app)


class TestNothingIsRecordedBeforeTheProof:
    async def test_a_missing_token_is_invalid_request(
        self, app: Starlette, clean: Database
    ) -> None:
        response = await _refresh(app, None)
        assert response.status_code == 400
        assert response.json()["error"] == "invalid_request"
        assert response.headers["cache-control"] == "no-store"
        assert await _rows(clean) == []

    @pytest.mark.parametrize(
        "value", ["garbage", "prt1.short.value", "prt2." + "a" * 22 + "." + "b" * 43]
    )
    async def test_a_malformed_token_is_invalid_grant(
        self, app: Starlette, clean: Database, value: str
    ) -> None:
        _refused(await _refresh(app, value))
        assert await _rows(clean) == []

    async def test_an_unknown_family_is_invalid_grant(
        self, app: Starlette, clean: Database
    ) -> None:
        _refused(await _refresh(app, new_refresh_token("A" * 22)))
        assert await _rows(clean) == []

    async def test_an_unserved_resource_is_invalid_target(
        self, app: Starlette, key_pair: RSAKeyPair, clean: Database
    ) -> None:
        first = await _session(app, key_pair)
        response = await _refresh(app, first["refresh_token"], resource="https://other.test/mcp")
        assert response.json()["error"] == "invalid_target"
        assert await _rows(clean) == []

    async def test_an_unknown_hash_under_a_real_family_writes_nothing_and_logs_once(
        self,
        app: Starlette,
        key_pair: RSAKeyPair,
        clean: Database,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        first = await _session(app, key_pair)
        forged = new_refresh_token(_sid(first))
        with caplog.at_level(logging.WARNING, logger="services.confirm.device_auth"):
            _refused(await _refresh(app, forged))
            _refused(await _refresh(app, new_refresh_token(_sid(first))))
        assert await _rows(clean) == []
        lines = [r for r in caplog.records if "never issued" in r.getMessage()]
        assert len(lines) == 1
        assert _sid(first) in lines[0].getMessage()
        assert forged not in caplog.text
        family = await _family(app, first)
        assert family.revoked_at is None and family.generation == 0


class TestReuse:
    async def test_a_retained_token_revokes_the_family_and_lists_every_live_jti(
        self,
        app: Starlette,
        key_pair: RSAKeyPair,
        clean: Database,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        first = await _session(app, key_pair)
        second = (await _refresh(app, first["refresh_token"])).json()
        with caplog.at_level(logging.WARNING, logger="services.confirm.device_auth"):
            _refused(await _refresh(app, first["refresh_token"]))
        family = await _family(app, first)
        assert family.revoked_reason == "reuse"
        assert "is revoked" in caplog.text and family.device_code_handle in caplog.text
        revocations: InMemoryRevocationStore = app.state.postern_revocation_store
        for jti, _ in family.access_tokens:
            assert await revocations.is_revoked({"jti": jti})

        _refused(await _refresh(app, second["refresh_token"]))
        assert [r.detail for r in await _rows(clean)] == [
            None,
            DETAIL_REFRESH_REUSED,
            DETAIL_SESSION_REVOKED,
        ]

    async def test_a_failed_zt7_write_at_reuse_converges_on_the_next_presentation(
        self,
        app: Starlette,
        key_pair: RSAKeyPair,
        clean: Database,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        first = await _session(app, key_pair)
        second = (await _refresh(app, first["refresh_token"])).json()
        revocations: InMemoryRevocationStore = app.state.postern_revocation_store
        real = revocations.revoke_session

        async def down(*, jti: str) -> None:
            raise RevocationStoreUnavailable("simulated outage")

        monkeypatch.setattr(revocations, "revoke_session", down)
        outage = await _refresh(app, first["refresh_token"])
        assert outage.status_code == 503
        family = await _family(app, first)
        assert family.revoked_at is not None
        jtis = [jti for jti, _ in family.access_tokens]
        assert not await revocations.is_revoked({"jti": jtis[0]})

        monkeypatch.setattr(revocations, "revoke_session", real)
        _refused(await _refresh(app, second["refresh_token"]))
        for jti in jtis:
            assert await revocations.is_revoked({"jti": jti})
        assert [r.detail for r in await _rows(clean)] == [
            None,
            "RevocationStoreUnavailable",
            DETAIL_SESSION_REVOKED,
        ]


class TestTheFamilysLimits:
    async def test_exhausted_generations(
        self, app: Starlette, key_pair: RSAKeyPair, clean: Database
    ) -> None:
        first = await _session(app, key_pair)
        sessions: InMemoryRefreshSessionStore = app.state.refresh_session_store
        sid = _sid(first)
        sessions._sessions[sid] = dataclasses.replace(
            sessions._sessions[sid], generation=MAX_GENERATIONS
        )
        _refused(await _refresh(app, first["refresh_token"]))
        assert [r.detail for r in await _rows(clean)] == [DETAIL_SESSION_GENERATIONS_EXHAUSTED]

    async def test_a_family_past_its_lifetime(
        self,
        app: Starlette,
        key_pair: RSAKeyPair,
        clean: Database,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The store's ``get`` filters an expired family (answered with no
        row); this reaches the handler's own check, which a family expiring
        between the lookup and the classification meets."""
        first = await _session(app, key_pair)
        sessions: InMemoryRefreshSessionStore = app.state.refresh_session_store
        sid = _sid(first)
        past = datetime.now(UTC) - timedelta(seconds=1)
        expired = dataclasses.replace(sessions._sessions[sid], expires_at=past)
        sessions._sessions[sid] = expired

        async def unfiltered(wanted: str) -> RefreshSession | None:
            return sessions._sessions.get(wanted)

        monkeypatch.setattr(sessions, "get", unfiltered)
        _refused(await _refresh(app, first["refresh_token"]))
        assert [r.detail for r in await _rows(clean)] == [DETAIL_SESSION_EXPIRED]

    async def test_an_expired_family_is_unknown_to_the_lookup(
        self, app: Starlette, key_pair: RSAKeyPair, clean: Database
    ) -> None:
        first = await _session(app, key_pair)
        sessions: InMemoryRefreshSessionStore = app.state.refresh_session_store
        sid = _sid(first)
        sessions._sessions[sid] = dataclasses.replace(
            sessions._sessions[sid], expires_at=datetime.now(UTC) - timedelta(seconds=1)
        )
        _refused(await _refresh(app, first["refresh_token"]))
        assert await _rows(clean) == []

    async def test_a_client_id_that_is_not_the_pairings(
        self, app: Starlette, key_pair: RSAKeyPair, clean: Database
    ) -> None:
        first = await _session(app, key_pair)
        _refused(await _refresh(app, first["refresh_token"], client_id="claude-code2"))
        assert [r.detail for r in await _rows(clean)] == [DETAIL_CLIENT_ID_MISMATCH]
        assert (await _family(app, first)).generation == 0


class TestScope:
    @pytest.mark.parametrize("scope", ["", "   "])
    async def test_empty_is_the_original_grant(
        self, app: Starlette, key_pair: RSAKeyPair, clean: Database, scope: str
    ) -> None:
        first = await _session(app, key_pair)
        response = await _refresh(app, first["refresh_token"], scope=scope)
        assert session_claims(response, app)["scope"] == SCOPES

    async def test_duplicates_and_order_are_canonicalized_and_narrowing_narrows_this_token_only(
        self, app: Starlette, key_pair: RSAKeyPair, clean: Database
    ) -> None:
        first = await _session(app, key_pair)
        narrowed = await _refresh(
            app, first["refresh_token"], scope="cards:read accounts:read cards:read"
        )
        assert session_claims(narrowed, app)["scope"] == "accounts:read cards:read"
        assert (await _family(app, first)).scopes == SCOPES
        again = await _refresh(app, narrowed.json()["refresh_token"])
        assert session_claims(again, app)["scope"] == SCOPES

    async def test_a_wider_scope_is_invalid_scope(
        self, app: Starlette, key_pair: RSAKeyPair, clean: Database
    ) -> None:
        first = await _session(app, key_pair)
        response = await _refresh(app, first["refresh_token"], scope="accounts:read payments:write")
        assert response.status_code == 400
        assert response.json()["error"] == "invalid_scope"
        assert [r.detail for r in await _rows(clean)] == [DETAIL_SCOPE_EXCEEDED]


class TestZt7:
    async def _refused_as_revoked(
        self, app: Starlette, body: dict[str, Any], clean: Database
    ) -> None:
        _refused(await _refresh(app, body["refresh_token"]))
        (row,) = await _rows(clean)
        assert (row.outcome, row.detail) == (OUTCOME_RAISED, DETAIL_REVOKED)
        family = await _family(app, body)
        assert family.generation == 0
        assert family.revoked_at is None, "the first two checks do not revoke the family"

    async def test_a_revoked_customer(
        self, app: Starlette, key_pair: RSAKeyPair, clean: Database
    ) -> None:
        first = await _session(app, key_pair)
        await app.state.postern_revocation_store.revoke_customer_client(
            customer_ref=CUSTOMER, client_id="some-other-client"
        )
        store: InMemoryRevocationStore = app.state.postern_revocation_store
        store._revoked_at.clear()
        await self._refused_as_revoked(app, first, clean)

    async def test_the_kill_switch(
        self, app: Starlette, key_pair: RSAKeyPair, clean: Database
    ) -> None:
        first = await _session(app, key_pair)
        await app.state.postern_revocation_store.kill_switch(client_id="claude-code")
        await self._refused_as_revoked(app, first, clean)

    async def test_a_live_access_tokens_jti(
        self, app: Starlette, key_pair: RSAKeyPair, clean: Database
    ) -> None:
        first = await _session(app, key_pair)
        await app.state.postern_revocation_store.revoke_session(jti=_jti(first))
        await self._refused_as_revoked(app, first, clean)

    async def test_a_family_created_before_a_since_restored_revocation_is_refused_and_revoked(
        self, app: Starlette, key_pair: RSAKeyPair, clean: Database
    ) -> None:
        first = await _session(app, key_pair)
        store: InMemoryRevocationStore = app.state.postern_revocation_store
        await store.revoke_customer_client(customer_ref=CUSTOMER, client_id="claude-code")
        await store.restore_customer_client(customer_ref=CUSTOMER, client_id="claude-code")
        _refused(await _refresh(app, first["refresh_token"]))
        family = await _family(app, first)
        assert family.revoked_reason == "issued_before_revocation"
        assert [r.detail for r in await _rows(clean)] == [DETAIL_ISSUED_BEFORE_REVOCATION]

    @pytest.mark.parametrize(("offset_ms", "refused"), [(700, True), (0, True), (-1, False)])
    async def test_milliseconds_decide_at_the_edge(
        self,
        app: Starlette,
        key_pair: RSAKeyPair,
        clean: Database,
        offset_ms: int,
        refused: bool,
    ) -> None:
        """A family created at .200 and a revocation at .900 of the same second
        is refused: whole seconds would have compared 0 against 0.2."""
        first = await _session(app, key_pair)
        family = await _family(app, first)
        store: InMemoryRevocationStore = app.state.postern_revocation_store
        store._revoked_at[CUSTOMER] = (family.created_ms + offset_ms, 2**62)
        response = await _refresh(app, first["refresh_token"])
        if refused:
            _refused(response)
        else:
            session_claims(response, app)

    async def test_an_outage_answers_503_and_rotates_nothing(
        self,
        app: Starlette,
        key_pair: RSAKeyPair,
        clean: Database,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        first = await _session(app, key_pair)
        store: InMemoryRevocationStore = app.state.postern_revocation_store

        async def down(customer_ref: str) -> bool:
            raise RevocationStoreUnavailable("simulated outage")

        monkeypatch.setattr(store, "is_customer_revoked", down)
        response = await _refresh(app, first["refresh_token"])
        assert response.status_code == 503
        assert response.json()["error"] == "temporarily_unavailable"
        assert (await _family(app, first)).generation == 0
        assert [r.detail for r in await _rows(clean)] == ["RevocationStoreUnavailable"]


class TestTheRotationItself:
    async def test_a_contended_rotation_propagates_and_is_recorded(
        self,
        app: Starlette,
        key_pair: RSAKeyPair,
        clean: Database,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        first = await _session(app, key_pair)
        sessions: InMemoryRefreshSessionStore = app.state.refresh_session_store

        async def contended(*args: Any, **kwargs: Any) -> Any:
            raise RefreshSessionStoreContended("beaten three times")

        monkeypatch.setattr(sessions, "rotate", contended)
        response = await _refresh(app, first["refresh_token"])
        assert response.status_code == 500
        assert [r.detail for r in await _rows(clean)] == ["RefreshSessionStoreContended"]

    async def test_a_concurrent_winner_turns_this_refresh_into_reuse(
        self,
        app: Starlette,
        key_pair: RSAKeyPair,
        clean: Database,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Another replica rotates between this one's classification and its
        compare-and-set: the transaction sees a retained hash and revokes."""
        first = await _session(app, key_pair)
        sessions: InMemoryRefreshSessionStore = app.state.refresh_session_store
        real_rotate = sessions.rotate

        async def raced(sid: str, **kwargs: Any) -> Any:
            await real_rotate(
                sid,
                presented_hash=kwargs["presented_hash"],
                new_hash="f" * 64,
                access_jti="winner",
                access_expires_at=datetime.now(UTC) + timedelta(minutes=10),
            )
            return await real_rotate(sid, **kwargs)

        monkeypatch.setattr(sessions, "rotate", raced)
        _refused(await _refresh(app, first["refresh_token"]))
        assert (await _family(app, first)).revoked_reason == "reuse"
        assert [r.detail for r in await _rows(clean)] == [DETAIL_REFRESH_REUSED]
```

- [ ] **Step 2: Run them to verify they fail**

Run: `uv run pytest tests/test_refresh_grant.py -q`

Expected: FAIL, `1 error`. The first failure reads `ImportError: cannot import name 'DETAIL_CLIENT_ID_MISMATCH' from 'services.confirm.audit'`.

- [ ] **Step 3: Implement**

In `services/confirm/audit.py`, replace:

```python

#: The stored ``customer_ref`` on an approved device code will not parse as a
```

with:

```python

#: What ``tool_name`` carries on a ``POST /token`` row for
#: ``grant_type=refresh_token``, written only once the caller has shown a
#: refresh token the family issued. Its own literal, so "sessions issued" and
#: "refreshes issued" are two predicates on ``tool_name`` and never a
#: ``detail`` filter; ``route`` stays ``TOKEN_ROUTE``.
REFRESH_TOOL_NAME = "device_grant.refresh"

#: The stored ``customer_ref`` on an approved device code will not parse as a
```

In `services/confirm/audit.py`, replace:

```python
DETAIL_USER_CODE_BUDGET_EXHAUSTED = "user_code_budget_exhausted"

```

with:

```python
DETAIL_USER_CODE_BUDGET_EXHAUSTED = "user_code_budget_exhausted"

# THE REFRESH GRANT'S REFUSALS, spec section 6. Every one is written only past
# the proof of possession (a presented refresh token whose hash the family
# holds), so a caller who has merely seen an access token, and therefore the
# family id, cannot drive an INSERT against a named customer. An unknown hash
# under a real family id has no literal because it has no row.

#: A retained (already rotated) refresh token was presented: two parties hold
#: one family. The family is revoked in the same transaction that noticed, and
#: every live access token of it goes on the ZT-7 list.
DETAIL_REFRESH_REUSED = "refresh_reused"
#: The family was already revoked (by reuse, by a recall at ``POST /scan``, or
#: as issued before a customer revocation); its live access tokens are
#: re-asserted on the ZT-7 list, which is what makes a failed write converge.
DETAIL_SESSION_REVOKED = "session_revoked"
#: The family is past its absolute one-hour lifetime.
DETAIL_SESSION_EXPIRED = "session_expired"
#: The family has rotated ``MAX_GENERATIONS`` times; the customer re-pairs.
DETAIL_SESSION_GENERATIONS_EXHAUSTED = "session_generations_exhausted"
#: A ``client_id`` parameter that is not byte-equal to the pairing's. It
#: authenticates nothing, both being caller-supplied: a transplant signal.
DETAIL_CLIENT_ID_MISMATCH = "client_id_mismatch"
#: A requested ``scope`` wider than the family's (RFC 6749 section 6).
DETAIL_SCOPE_EXCEEDED = "scope_exceeded"
#: The family was created at or before a customer revocation, whether or not
#: that revocation has since been restored; the family is revoked for good.
DETAIL_ISSUED_BEFORE_REVOCATION = "issued_before_revocation"

```

In `services/confirm/device_auth.py`, replace:

```python
import dataclasses
import json
```

with:

```python
import dataclasses
import hmac
import json
```

In `services/confirm/device_auth.py`, replace:

```python
import uuid
from datetime import UTC, datetime, timedelta
```

with:

```python
import uuid
from collections import OrderedDict
from datetime import UTC, datetime, timedelta
```

In `services/confirm/device_auth.py`, replace:

```python
from postern_core.auth.refresh_sessions import (
    RefreshSession,
```

with:

```python
from postern_core.auth.refresh_sessions import (
    MAX_GENERATIONS,
    RefreshSession,
```

In `services/confirm/device_auth.py`, replace:

```python
    RefreshSessionStoreFull,
    canonical_scope,
```

with:

```python
    RefreshSessionStoreFull,
    Rotation,
    canonical_scope,
```

In `services/confirm/device_auth.py`, replace:

```python
    new_sid,
)
from postern_core.auth.resource_uri import normalize_resource
from postern_core.auth.revocation import RevocationStoreUnavailable
from postern_core.identity import CustomerRef
```

with:

```python
    new_sid,
    sid_of,
)
from postern_core.auth.resource_uri import normalize_resource
from postern_core.auth.revocation import RevocationStoreBase, RevocationStoreUnavailable
from postern_core.identity import CustomerRef
```

In `services/confirm/device_auth.py`, replace:

```python
    DETAIL_ALREADY_SCANNED,
    DETAIL_DEVICE_CODE_SPENT,
    DETAIL_INVALID_SUBJECT,
    DETAIL_NOT_SCANNED,
```

with:

```python
    DETAIL_ALREADY_SCANNED,
    DETAIL_CLIENT_ID_MISMATCH,
    DETAIL_DEVICE_CODE_SPENT,
    DETAIL_INVALID_SUBJECT,
    DETAIL_ISSUED_BEFORE_REVOCATION,
    DETAIL_NOT_SCANNED,
```

In `services/confirm/device_auth.py`, replace:

```python
    DETAIL_QR_STALE,
    DETAIL_REVOKED,
```

with:

```python
    DETAIL_QR_STALE,
    DETAIL_REFRESH_REUSED,
    DETAIL_REVOKED,
```

In `services/confirm/device_auth.py`, replace:

```python
    DETAIL_SCANNED_BY_OTHER,
    DETAIL_STORED_IDENTITY_MALFORMED,
    DETAIL_USER_CODE_NOT_FOUND,
    SCAN_ROUTE,
```

with:

```python
    DETAIL_SCANNED_BY_OTHER,
    DETAIL_SCOPE_EXCEEDED,
    DETAIL_SESSION_EXPIRED,
    DETAIL_SESSION_GENERATIONS_EXHAUSTED,
    DETAIL_SESSION_REVOKED,
    DETAIL_STORED_IDENTITY_MALFORMED,
    DETAIL_USER_CODE_NOT_FOUND,
    REFRESH_TOOL_NAME,
    SCAN_ROUTE,
```

In `services/confirm/device_auth.py`, replace:

```python
    log_refusal,
    revoked_response,
```

with:

```python
    log_refusal,
    revocation_store,
    revoked_response,
```

In `services/confirm/device_auth.py`, replace:

```python
APPROVAL_CLOCK_TOLERANCE_MS = 2_000

```

with:

```python
APPROVAL_CLOCK_TOLERANCE_MS = 2_000

#: How often one family's unknown-hash presentations may reach the log, per
#: process, and how many families the limiter remembers (oldest evicted).
UNKNOWN_REFRESH_LOG_INTERVAL_SECONDS = 60
UNKNOWN_REFRESH_LOG_ENTRIES = 4_096

```

In `services/confirm/device_auth.py`, replace:

```python

    if grant_type != "device_code":
        # Not a device code request — let the 404 handler deal with it.
        return _error(404, "unsupported_grant_type", "only device_code grant is supported")

```

with:

```python

    if grant_type == "refresh_token":
        return await _refresh_grant(request, form, at=at, started=started)
    if grant_type != "device_code":
        # Neither grant this endpoint serves. A 404, where RFC 6749 section
        # 5.2's error responses are 400; kept as it was (spec, Discrepancies).
        return _error(
            404,
            "unsupported_grant_type",
            "only the device_code and refresh_token grants are supported",
        )

```

In `services/confirm/device_auth.py`, replace:

```python
        None,
    )


```

with:

```python
        None,
    )


# ---------------------------------------------------------------------------
# Token endpoint -- POST /token with grant_type=refresh_token.
# ---------------------------------------------------------------------------


def _form_value(form: Any, name: str) -> str | None:
    """A form field as a string, ``None`` when absent. A file part is read."""
    raw = form.get(name)
    if raw is None:
        return None
    return raw.file.read().decode() if hasattr(raw, "file") else str(raw)


def _unrefreshable_response() -> JSONResponse:
    """The one ``invalid_grant`` every refused refresh gets.

    RFC 6749 section 5.2's code for a grant that is "invalid, expired,
    revoked ... or was issued to another client". One body for every reason,
    for the reason `_unredeemable_response` gives: the distinction belongs in
    ``audit_log.detail``, where the caller cannot read it.
    """
    return _error(400, "invalid_grant", "refresh token cannot be redeemed")


def _log_unknown_refresh(request: Request, sid: str) -> None:
    """One warning per family per `UNKNOWN_REFRESH_LOG_INTERVAL_SECONDS`, per process.

    A presented value whose ``sid`` names a real family and whose hash the
    family never issued. It proves nothing (the ``sid`` is in every access
    token), so it writes no row; the log line is rate-limited so the same
    caller cannot flood the log instead. The ``sid`` is logged, never the
    presented value.
    """
    seen: OrderedDict[str, float] | None = getattr(request.app.state, "_unknown_refresh_log", None)
    if seen is None:
        seen = OrderedDict()
        request.app.state._unknown_refresh_log = seen
    now = time.monotonic()
    last = seen.get(sid)
    if last is not None and now - last < UNKNOWN_REFRESH_LOG_INTERVAL_SECONDS:
        return
    seen.pop(sid, None)
    seen[sid] = now
    while len(seen) > UNKNOWN_REFRESH_LOG_ENTRIES:
        seen.popitem(last=False)
    logger.warning(
        "refresh grant: a refresh token this family never issued was presented for family %s",
        sid,
    )


async def _reassert(store: RevocationStoreBase, jtis: tuple[str, ...]) -> None:
    """Put every live access token of a revoked family on the ZT-7 list.

    An idempotent set add per ``jti``. Re-running it on every presentation of
    a revoked family is what makes a failed write at reuse or recall converge.
    """
    for jti in jtis:
        await store.revoke_session(jti=jti)


async def _refresh_grant(
    request: Request, form: Any, *, at: datetime, started: float
) -> JSONResponse:
    """``grant_type=refresh_token``, spec section 6 steps 1 to 3 and the row.

    The shape checks and the lookup write nothing. From the proof of
    possession on -- the presented token's hash is the family's current one
    or a retained one -- every exit writes exactly one row, through
    ``PairingAudit`` with ``REFRESH_TOOL_NAME``, naming the family's customer
    and ``session_id``.
    """
    settings: ConfirmSettings = request.app.state.settings
    presented = _form_value(form, "refresh_token")
    if not presented:
        return _error(400, "invalid_request", "refresh_token is required")
    unserved = _resource_refusal(form, settings)
    if unserved is not None:
        return unserved
    sid = sid_of(presented)
    if sid is None:
        return _unrefreshable_response()
    sessions: RefreshSessionStoreBase = request.app.state.refresh_session_store
    family = await sessions.get(sid)
    if family is None:
        return _unrefreshable_response()

    # STEP 3: PROOF OF POSSESSION BEFORE ANYTHING IS RECORDED.
    presented_hash = hash_refresh_token(presented)
    retained = presented_hash in family.retained_hashes
    if not retained and not hmac.compare_digest(family.current_hash, presented_hash):
        _log_unknown_refresh(request, sid)
        return _unrefreshable_response()

    db: Database = request.app.state.postern_database
    audit = PairingAudit(
        db=db,
        call_id=str(uuid.uuid4()),
        at=at,
        started=started,
        subject=family.customer_ref,
        claims={},
        client_ip_value=pairing_client_ip(request, settings.trusted_proxy_hops),
        tool_name=REFRESH_TOOL_NAME,
        route=TOKEN_ROUTE,
    )
    audit.names(session_id=sid, paired_client_id=family.client_id)
    try:
        response, detail = await _refresh(
            request, form=form, family=family, presented_hash=presented_hash, retained=retained
        )
    except Exception as exc:
        try:
            await audit.refused(type(exc).__name__)
        except Exception as audit_exc:
            logger.error(
                "audit write failed for a session refresh after it raised %s: %s",
                type(exc).__name__,
                audit_exc,
                exc_info=audit_exc,
            )
            raise exc from audit_exc
        raise
    # COMMITTED BEFORE THE RESPONSE, for the reason `_token_response` gives.
    try:
        if detail is None:
            await audit.minted()
        else:
            await audit.refused(detail)
    except Exception as audit_exc:
        logger.error(
            "audit write failed for a session refresh that answered %d; failing the request",
            response.status_code,
            exc_info=audit_exc,
        )
        raise
    return response


async def _refresh(
    request: Request,
    *,
    form: Any,
    family: RefreshSession,
    presented_hash: str,
    retained: bool,
) -> tuple[JSONResponse, str | None]:
    """Spec section 6 steps 4 to 9, returning ``(response, detail)``.

    ``detail`` is ``None`` only for a rotation that issued a session. The
    ZT-7 checks run before the rotation spends anything, the ordering
    ``_exchange`` argues for its claim.
    """
    sessions: RefreshSessionStoreBase = request.app.state.refresh_session_store
    revocations = revocation_store(request)
    now = datetime.now(UTC)

    # STEP 4: CLASSIFY.
    if family.revoked_at is not None:
        return await _answer_revoked(revocations, family, now)
    if retained:
        return await _answer_reuse(sessions, revocations, family)
    if family.generation >= MAX_GENERATIONS:
        return _unrefreshable_response(), DETAIL_SESSION_GENERATIONS_EXHAUSTED
    if family.is_expired(now):
        return _unrefreshable_response(), DETAIL_SESSION_EXPIRED
    client_id = _form_value(form, "client_id")
    if client_id is not None and client_id != family.client_id:
        return _unrefreshable_response(), DETAIL_CLIENT_ID_MISMATCH

    # STEP 5: SCOPE. Absent or empty after canonicalization is "the scope
    # originally granted" (RFC 6749 section 6); wider is refused.
    requested = canonical_scope(_form_value(form, "scope") or "")
    granted = family.scopes
    if requested:
        if not set(requested.split(" ")) <= set(family.scopes.split(" ")):
            return (
                _error(400, "invalid_scope", "the requested scope exceeds the grant"),
                DETAIL_SCOPE_EXCEEDED,
            )
        granted = requested

    # STEP 6: ZT-7, BEFORE THE ROTATION SPENDS ANYTHING.
    try:
        refused = await _refresh_revoked(revocations, family, now)
        stamp = await revocations.customer_revoked_at(family.customer_ref)
    except RevocationStoreUnavailable as exc:
        logger.warning("refresh grant: revocation store unavailable, refusing to rotate")
        return store_unavailable_response(), type(exc).__name__
    if refused:
        log_refusal("a session refresh")
        return _unrefreshable_response(), DETAIL_REVOKED
    if stamp is not None and stamp >= family.created_ms:
        # ISSUED BEFORE A CUSTOMER REVOCATION: refused, and the family is
        # revoked for good, so no later restore can revive it.
        log_refusal("a session refresh of a family issued before a revocation")
        await sessions.revoke(family.sid, reason="issued_before_revocation")
        return _unrefreshable_response(), DETAIL_ISSUED_BEFORE_REVOCATION

    # STEP 7: DRAW.
    minter: SessionTokenMinter = request.app.state.session_minter
    new_token = new_refresh_token(family.sid)
    claims = minter.prepare(
        customer=CustomerRef(value=family.customer_ref),
        client_id=family.client_id,
        scope=granted,
        sid=family.sid,
    )

    # STEP 8: ROTATE, one compare-and-set. Any result but ROTATED re-runs the
    # matching branch of step 4 against what the transaction saw: a
    # concurrent refresh that won turns this one into REUSED.
    outcome = await sessions.rotate(
        family.sid,
        presented_hash=presented_hash,
        new_hash=hash_refresh_token(new_token),
        access_jti=claims.jti,
        access_expires_at=datetime.fromtimestamp(claims.exp, UTC),
    )
    if outcome.rotation is Rotation.REUSED:
        return await _reuse_detected(revocations, family, outcome.jtis)
    if outcome.rotation is Rotation.REVOKED:
        try:
            await _reassert(revocations, outcome.jtis)
        except RevocationStoreUnavailable as exc:
            return store_unavailable_response(), type(exc).__name__
        return _unrefreshable_response(), DETAIL_SESSION_REVOKED
    if outcome.rotation is Rotation.EXHAUSTED:
        return _unrefreshable_response(), DETAIL_SESSION_GENERATIONS_EXHAUSTED
    if outcome.rotation is Rotation.GONE:
        return _unrefreshable_response(), DETAIL_SESSION_EXPIRED
    if outcome.rotation is not Rotation.ROTATED:
        # UNKNOWN after step 3's proof means the record was replaced under a
        # presentation it had accepted. Fail closed and loudly: the row
        # records the exception's type.
        raise RuntimeError(f"family {family.sid} no longer holds a hash it held a moment ago")

    # STEP 9: SIGN. A raise leaves the family rotated and the client's token
    # retained; its retry is reuse and revokes the family. Fail closed.
    access_token = minter.sign(claims)
    return (
        JSONResponse(
            status_code=200,
            content={
                "access_token": access_token,
                "token_type": "Bearer",
                "expires_in": ACCESS_TOKEN_LIFETIME_SECONDS,
                "refresh_token": new_token,
                "scope": granted,
            },
        ),
        None,
    )


async def _refresh_revoked(
    revocations: RevocationStoreBase, family: RefreshSession, now: datetime
) -> bool:
    """The first two ZT-7 checks of spec section 6 step 6.

    The customer under any client, as ``/token`` asks; then the pair and the
    kill switch, once on their own and once beside each live access ``jti``,
    so an operator who revokes a live access token's ``jti`` also stops the
    family refreshing past it. The check without a ``jti`` is there for a
    family whose access tokens have all expired, which would otherwise ask
    the pair and the kill switch nothing.
    """
    if await revocations.is_customer_revoked(family.customer_ref):
        return True
    base = {"sub": family.customer_ref, "client_id": family.client_id}
    if await revocations.is_revoked(base):
        return True
    for jti in family.live_jtis(now):
        if await revocations.is_revoked({**base, "jti": jti}):
            return True
    return False


async def _answer_revoked(
    revocations: RevocationStoreBase, family: RefreshSession, now: datetime
) -> tuple[JSONResponse, str | None]:
    """A revoked family: re-assert its live jtis on the ZT-7 list, then refuse."""
    try:
        await _reassert(revocations, family.live_jtis(now))
    except RevocationStoreUnavailable as exc:
        return store_unavailable_response(), type(exc).__name__
    return _unrefreshable_response(), DETAIL_SESSION_REVOKED


async def _answer_reuse(
    sessions: RefreshSessionStoreBase,
    revocations: RevocationStoreBase,
    family: RefreshSession,
) -> tuple[JSONResponse, str | None]:
    """A retained token on a live family: revoke it, then list its jtis.

    A store raising answers 503 under its type name; the next presentation of
    either token lands in the revoked branch and re-asserts.
    """
    try:
        jtis = await sessions.revoke(family.sid, reason="reuse")
    except Exception as exc:  # noqa: BLE001 -- any store failure is a retryable 503
        return store_unavailable_response(), type(exc).__name__
    return await _reuse_detected(revocations, family, jtis or ())


async def _reuse_detected(
    revocations: RevocationStoreBase, family: RefreshSession, jtis: tuple[str, ...]
) -> tuple[JSONResponse, str | None]:
    logger.warning(
        "refresh grant: a retained refresh token was presented; family %s (device code %s) "
        "is revoked",
        family.sid,
        family.device_code_handle,
    )
    try:
        await _reassert(revocations, jtis)
    except RevocationStoreUnavailable as exc:
        return store_unavailable_response(), type(exc).__name__
    return _unrefreshable_response(), DETAIL_REFRESH_REUSED


```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `uv run pytest tests/test_refresh_grant.py -q`

Expected: 29 passed

- [ ] **Step 5: Format, then run the gate**

Run: `uv run ruff format packages services tests && make ci`

Expected: exit 0 (3710 passed at validation).

- [ ] **Step 6: Commit**

```bash
git add services/confirm/audit.py services/confirm/device_auth.py tests/test_refresh_grant.py
git commit -m "feat(confirm): the refresh_token grant" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 8: Session-swap recall at `POST /scan`

Spec section 7: on `CONFLICT_EXCHANGED` only, re-read the row, revoke the family, list its access tokens, then write the recall row (naming the family's customer, sharing the scan row's `call_id`) before the scan row. A failure answers 503 with `Retry-After: 1` and still writes both rows. `recall_local_only` is recorded when the stores are this process's own, which `create_confirm_app` now remembers on `app.state`.

**Files:**
- Modify: `packages/postern-core/src/postern_core/auth/device_codes.py` (`ScanClaim.CONFLICT_EXCHANGED`'s comment)
- Modify: `services/confirm/audit.py` (`RECALL_TOOL_NAME`, `DETAIL_RECALL_NO_SESSION`, `DETAIL_RECALL_LOCAL_ONLY`, `PairingAudit.recalled`)
- Modify: `services/confirm/device_auth.py` (`_recall_retry_response`, `_scan`, `_recall`)
- Modify: `services/confirm/main.py` (`_refuse_process_local_sessions` returns a bool; `app.state.process_local_sessions`)
- Modify: `tests/test_scan.py`
- Create: `tests/test_scan_recall.py`

- [ ] **Step 1: Write the failing tests**

In `tests/test_scan.py`, replace:

```python

async def test_session_swap_after_the_exchange_is_refused_with_nothing_revoked(
    app: Starlette, clean: Database, key_pair: RSAKeyPair
) -> None:
    """The window this spec does not close: B's token is already out. The
    conflict is refused and recorded; the spent row is left exactly as it was,
    because revoking it would recall nothing.

    SPENT THROUGH THE STORE since 2026-09-30: ``POST /token`` spends nothing
    while issuance is disabled, so the spent state is reached the way an
    earlier build left it, and the way the session-token change will again."""
    code = await start(app)
```

with:

```python

async def test_session_swap_after_the_exchange_is_refused_and_leaves_the_row(
    app: Starlette, clean: Database, key_pair: RSAKeyPair
) -> None:
    """The conflict is refused and recorded, and the spent row is left exactly
    as it was: revoking a spent code recalls nothing. What IS recalled is the
    session the exchange issued, through its ``session_id``;
    ``tests/test_scan_recall.py`` holds that. Spent here through the store with
    no family, so the recall row records nothing to recall."""
    code = await start(app)
```

Create `tests/test_scan_recall.py` with:

```python
"""Session-swap recall at ``POST /scan`` (spec section 7).

Customer B scans victim A's QR first and approves; A's AI client exchanges
and receives a session for B's accounts; A's scan then arrives and
``claim_scan`` answers ``CONFLICT_EXCHANGED``. The family is revoked, its
access tokens go on the ZT-7 list, and two rows share one ``call_id``: the
recall row naming B, then the scan row naming A. The end-to-end half, A's
client refused at the assembled ``services/api``, is in
``tests/test_session_end_to_end.py``.
"""

from __future__ import annotations

import base64
import json
import logging
from collections.abc import AsyncIterator
from dataclasses import replace
from typing import Any
from uuid import uuid4

import pytest
from fastmcp.server.auth.providers.jwt import JWTVerifier, RSAKeyPair
from postern_core.auth.device_codes import DeviceCode
from postern_core.auth.device_keys import no_enrolled_devices
from postern_core.auth.refresh_sessions import RefreshSessionStoreBase
from postern_core.auth.revocation import RevocationStoreBase
from postern_core.store.engine import Database
from postern_core.store.models import OUTCOME_RAISED, OUTCOME_RETURNED, AuditEntry
from sqlalchemy import select
from starlette.applications import Starlette

from services.confirm.audit import (
    DETAIL_QR_STALE,
    DETAIL_RECALL_LOCAL_ONLY,
    DETAIL_RECALL_NO_SESSION,
    DETAIL_SCAN_CONFLICT,
    DETAIL_SESSION_REVOKED,
    RECALL_TOOL_NAME,
    SCAN_ROUTE,
    SCAN_TOOL_NAME,
)
from services.confirm.main import create_confirm_app
from services.confirm.settings import ConfirmSettings
from tests.device_grant_helpers import device_store_of, qr_for, session_claims
from tests.fixtures.append_only_bypass import (
    delete_audit_rows_by_bypassing_the_append_only_triggers,
)
from tests.test_scan import ALICE, AUDIENCE, BOB, ISSUER, bearer, post, scan, start


@pytest.fixture(scope="module")
def key_pair() -> RSAKeyPair:
    return RSAKeyPair.generate()


def _build(pg_url: str, key_pair: RSAKeyPair) -> Starlette:
    verifier = JWTVerifier(public_key=key_pair.public_key, issuer=ISSUER, audience=AUDIENCE)
    return create_confirm_app(
        replace(ConfirmSettings.for_testing(), database_url=pg_url),
        assertion_verifier=verifier,
        device_key_store=no_enrolled_devices(),
    )


@pytest.fixture()
def app(pg_url: str, key_pair: RSAKeyPair) -> Starlette:
    return _build(pg_url, key_pair)


@pytest.fixture()
def shared_app(
    pg_url: str, key_pair: RSAKeyPair, redis_url: str, monkeypatch: pytest.MonkeyPatch
) -> Starlette:
    """Every store on the suite's Redis, as a deployment runs."""
    monkeypatch.setenv("POSTERN_REDIS_URL", redis_url)
    monkeypatch.setenv("POSTERN_REDIS_KEY_PREFIX", f"rc{uuid4().hex[:12]}:")
    return _build(pg_url, key_pair)


@pytest.fixture()
async def clean(database: Database) -> AsyncIterator[Database]:
    async with database.sessionmaker() as s:
        await delete_audit_rows_by_bypassing_the_append_only_triggers(s)
        await s.commit()
    yield database


async def _rows(db: Database) -> list[AuditEntry]:
    async with db.sessionmaker() as s:
        return list((await s.execute(select(AuditEntry).order_by(AuditEntry.id))).scalars())


async def _swapped(app: Starlette, key_pair: RSAKeyPair) -> tuple[DeviceCode, dict[str, Any]]:
    """B scans and approves A's pairing; A's client exchanges. Returns the
    pairing and the session body A's client holds."""
    code = await start(app)
    assert (await scan(app, key_pair, BOB, code)).status_code == 200
    approved = await post(
        app,
        "/approve",
        json_body={"user_code": code.user_code_display},
        headers=bearer(key_pair, BOB),
    )
    assert approved.status_code == 200, approved.text
    exchanged = await post(
        app, "/token", form={"grant_type": "device_code", "device_code": code.device_code}
    )
    assert session_claims(exchanged, app)["sub"] == BOB
    return code, exchanged.json()


def _jti(body: dict[str, Any]) -> str:
    payload = body["access_token"].split(".")[1]
    return str(json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))["jti"])


def _sid(body: dict[str, Any]) -> str:
    return str(body["refresh_token"].split(".")[1])


async def _refresh(app: Starlette, body: dict[str, Any]) -> Any:
    return await post(
        app, "/token", form={"grant_type": "refresh_token", "refresh_token": body["refresh_token"]}
    )


class TestTheRecall:
    async def test_a_swap_after_the_exchange_recalls_the_session(
        self, shared_app: Starlette, key_pair: RSAKeyPair, clean: Database
    ) -> None:
        app = shared_app
        code, session = await _swapped(app, key_pair)

        response = await scan(app, key_pair, ALICE, code)

        assert response.status_code == 400
        assert response.json()["error"] == "scan_conflict"
        sessions: RefreshSessionStoreBase = app.state.refresh_session_store
        family = await sessions.get(_sid(session))
        assert family is not None and family.revoked_reason == "recall"
        revocations: RevocationStoreBase = app.state.postern_revocation_store
        assert await revocations.is_revoked({"jti": _jti(session)})

        refused = await _refresh(app, session)
        assert refused.json()["error"] == "invalid_grant"

        written = await _rows(clean)
        # B's scan, B's approval, the exchange, then this request's two rows
        # and the refused refresh.
        assert len(written) == 6
        recall, conflict = written[3], written[4]
        assert (recall.tool_name, recall.outcome, recall.detail) == (
            RECALL_TOOL_NAME,
            OUTCOME_RETURNED,
            None,
        )
        assert recall.customer_ref == BOB
        assert recall.arguments["route"] == SCAN_ROUTE
        assert recall.arguments["session_id"] == _sid(session)
        assert (conflict.tool_name, conflict.outcome, conflict.detail) == (
            SCAN_TOOL_NAME,
            OUTCOME_RAISED,
            DETAIL_SCAN_CONFLICT,
        )
        assert conflict.customer_ref == ALICE
        assert recall.call_id == conflict.call_id
        assert written[-1].detail == DETAIL_SESSION_REVOKED
        for secret in (session["access_token"], session["refresh_token"]):
            assert all(secret not in json.dumps(r.arguments) for r in written)

    async def test_under_process_local_stores_the_recall_says_so(
        self, app: Starlette, key_pair: RSAKeyPair, clean: Database
    ) -> None:
        code, session = await _swapped(app, key_pair)
        assert (await scan(app, key_pair, ALICE, code)).json()["error"] == "scan_conflict"
        recall = next(r for r in await _rows(clean) if r.tool_name == RECALL_TOOL_NAME)
        assert (recall.outcome, recall.detail) == (OUTCOME_RAISED, DETAIL_RECALL_LOCAL_ONLY)
        assert await app.state.postern_revocation_store.is_revoked({"jti": _jti(session)})

    async def test_a_code_spent_with_no_family_records_nothing_to_recall(
        self, app: Starlette, key_pair: RSAKeyPair, clean: Database
    ) -> None:
        code = await start(app)
        assert (await scan(app, key_pair, BOB, code)).status_code == 200
        assert await device_store_of(app).approve_scanned(code.device_code, BOB)
        assert await device_store_of(app).consume_device_code(code.device_code, session_id="")
        assert (await scan(app, key_pair, ALICE, code)).json()["error"] == "scan_conflict"
        recall = next(r for r in await _rows(clean) if r.tool_name == RECALL_TOOL_NAME)
        assert (recall.outcome, recall.detail) == (OUTCOME_RAISED, DETAIL_RECALL_NO_SESSION)
        assert recall.customer_ref == BOB

    async def test_a_conflict_before_the_exchange_recalls_nothing(
        self, app: Starlette, key_pair: RSAKeyPair, clean: Database
    ) -> None:
        code = await start(app)
        assert (await scan(app, key_pair, BOB, code)).status_code == 200
        assert (await scan(app, key_pair, ALICE, code)).json()["error"] == "scan_conflict"
        assert [r for r in await _rows(clean) if r.tool_name == RECALL_TOOL_NAME] == []


class TestTheRaceWithTheExchange:
    async def test_a_recall_between_the_claim_and_the_signature_lists_the_token_to_be_signed(
        self,
        shared_app: Starlette,
        key_pair: RSAKeyPair,
        clean: Database,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The family and its first ``jti`` exist before the code is spent, so a
        recall that lands after the claim and before the signature already
        names the token about to be signed."""
        app = shared_app
        code = await start(app)
        assert (await scan(app, key_pair, BOB, code)).status_code == 200
        assert (
            await post(
                app,
                "/approve",
                json_body={"user_code": code.user_code_display},
                headers=bearer(key_pair, BOB),
            )
        ).status_code == 200
        store = device_store_of(app)
        real = store.consume_device_code
        conflicts: list[Any] = []

        async def consume_then_recall(device_code: str, *, session_id: str) -> bool:
            won = await real(device_code, session_id=session_id)
            conflicts.append(await scan(app, key_pair, ALICE, code))
            return won

        monkeypatch.setattr(store, "consume_device_code", consume_then_recall)
        exchanged = await post(
            app, "/token", form={"grant_type": "device_code", "device_code": code.device_code}
        )

        session = exchanged.json()
        session_claims(exchanged, app)
        assert conflicts[0].json()["error"] == "scan_conflict"
        assert await app.state.postern_revocation_store.is_revoked({"jti": _jti(session)})


class TestFailure:
    async def test_a_failed_recall_answers_503_retry_after_1_and_writes_both_rows(
        self,
        shared_app: Starlette,
        key_pair: RSAKeyPair,
        clean: Database,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        app = shared_app
        code, session = await _swapped(app, key_pair)
        sessions: RefreshSessionStoreBase = app.state.refresh_session_store
        real = sessions.revoke

        async def down(sid: str, *, reason: str) -> tuple[str, ...] | None:
            raise ConnectionError("redis went away")

        monkeypatch.setattr(sessions, "revoke", down)
        with caplog.at_level(logging.ERROR, logger="services.confirm.device_auth"):
            failed = await scan(app, key_pair, ALICE, code)
        assert failed.status_code == 503
        assert failed.headers["retry-after"] == "1"
        recall, conflict = (await _rows(clean))[-2:]
        assert (recall.tool_name, recall.outcome, recall.detail) == (
            RECALL_TOOL_NAME,
            OUTCOME_RAISED,
            "ConnectionError",
        )
        assert (conflict.tool_name, conflict.detail) == (SCAN_TOOL_NAME, DETAIL_SCAN_CONFLICT)
        assert "may still be live" in caplog.text

        monkeypatch.setattr(sessions, "revoke", real)
        retried = await scan(app, key_pair, ALICE, code)
        assert retried.json()["error"] == "scan_conflict"
        family = await sessions.get(_sid(session))
        assert family is not None and family.revoked_reason == "recall"
        assert await app.state.postern_revocation_store.is_revoked({"jti": _jti(session)})

    async def test_a_retry_after_the_rotation_window_is_stale_and_recalls_nothing(
        self, shared_app: Starlette, key_pair: RSAKeyPair, clean: Database
    ) -> None:
        app = shared_app
        code, session = await _swapped(app, key_pair)
        late = await scan(app, key_pair, ALICE, code, qr=qr_for(code, slot_offset=-6))
        assert late.json()["error"] == "qr_stale"
        family = await app.state.refresh_session_store.get(_sid(session))
        assert family is not None and family.revoked_at is None
        assert (await _rows(clean))[-1].detail == DETAIL_QR_STALE
```

- [ ] **Step 2: Run them to verify they fail**

Run: `uv run pytest tests/test_scan.py tests/test_scan_recall.py -q`

Expected: FAIL, `1 error`. The first failure reads `ImportError: cannot import name 'DETAIL_RECALL_LOCAL_ONLY' from 'services.confirm.audit'`.

- [ ] **Step 3: Implement**

In `packages/postern-core/src/postern_core/auth/device_codes.py`, replace:

```python
    #: Another customer holds the scan and the code was already exchanged.
    #: Nothing written, because revoking a spent code recalls nothing.
    CONFLICT_EXCHANGED = "conflict_exchanged"
```

with:

```python
    #: Another customer holds the scan and the code was already exchanged.
    #: Nothing written here, because revoking a spent code recalls nothing:
    #: ``POST /scan`` recalls the session the exchange issued instead, through
    #: the ``session_id`` the exchange wrote on the row.
    CONFLICT_EXCHANGED = "conflict_exchanged"
```

In `services/confirm/audit.py`, replace:

```python

#: The stored ``customer_ref`` on an approved device code will not parse as a
```

with:

```python

#: What ``tool_name`` carries on the recall row ``POST /scan`` writes when a
#: second customer's scan finds the pairing already exchanged: the session
#: the exchange issued is revoked. ``route`` stays ``SCAN_ROUTE``, the row
#: names the recalled family's customer, and it shares the scan row's
#: ``call_id``.
RECALL_TOOL_NAME = "device_grant.recall"

#: The stored ``customer_ref`` on an approved device code will not parse as a
```

In `services/confirm/audit.py`, replace:

```python
DETAIL_ISSUED_BEFORE_REVOCATION = "issued_before_revocation"

```

with:

```python
DETAIL_ISSUED_BEFORE_REVOCATION = "issued_before_revocation"
#: A recall found nothing to recall: the exchanged row is gone, names no
#: family, or names one the store no longer holds.
DETAIL_RECALL_NO_SESSION = "recall_no_session"
#: A recall ran under ``POSTERN_ALLOW_PROCESS_LOCAL_SESSIONS``: it was written
#: to process-local stores that ``services/api`` does not read, so the access
#: token it named is still accepted there.
DETAIL_RECALL_LOCAL_ONLY = "recall_local_only"

```

In `services/confirm/audit.py`, replace:

```python

    async def refused(self, detail: str) -> None:
```

with:

```python

    async def recalled(self) -> None:
        """Record that a session a swap produced was recalled.

        ``returned`` with a NULL ``detail``, and its own method rather than
        ``minted``: only a ``POST /token`` row claims a session was issued.
        """
        await self._write(OUTCOME_RETURNED, None)

    async def refused(self, detail: str) -> None:
```

In `services/confirm/device_auth.py`, replace:

```python
    DETAIL_QR_STALE,
    DETAIL_REFRESH_REUSED,
```

with:

```python
    DETAIL_QR_STALE,
    DETAIL_RECALL_LOCAL_ONLY,
    DETAIL_RECALL_NO_SESSION,
    DETAIL_REFRESH_REUSED,
```

In `services/confirm/device_auth.py`, replace:

```python
    DETAIL_USER_CODE_NOT_FOUND,
    REFRESH_TOOL_NAME,
```

with:

```python
    DETAIL_USER_CODE_NOT_FOUND,
    RECALL_TOOL_NAME,
    REFRESH_TOOL_NAME,
```

In `services/confirm/device_auth.py`, replace:

```python

def _scan_context_response(code: DeviceCode) -> JSONResponse:
```

with:

```python

def _recall_retry_response() -> JSONResponse:
    """The 503 ``POST /scan`` answers when a recall could not complete.

    ``Retry-After: 1``, because the retry must land inside the rotation
    token's window: ``/scan`` checks the MAC before ``claim_scan``, so a retry
    later than 10 to 12 seconds answers ``qr_stale`` and recalls nothing. The
    mobile pairing contract tells the app to retry once, immediately.
    """
    return JSONResponse(
        status_code=503,
        content={
            "error": "temporarily_unavailable",
            "error_description": "the pairing could not be cancelled; retry now",
        },
        headers={"Retry-After": "1"},
    )


def _scan_context_response(code: DeviceCode) -> JSONResponse:
```

In `services/confirm/device_auth.py`, replace:

```python
    rows count first scans only.
    """
```

with:

```python
    rows count first scans only.

    ``CONFLICT_EXCHANGED`` RECALLS THE SESSION (spec section 7): the swap was
    noticed after the other customer's pairing was exchanged, so the family
    ``POST /token`` issued is revoked and its access tokens listed, before the
    ``scan_conflict`` answer. `_recall` carries the order and the failure mode.
    """
```

In `services/confirm/device_auth.py`, replace:

```python
        )
        return _Scanned(_scan_conflict_response(), DETAIL_SCAN_CONFLICT)
    return _Scanned(_unpairable_response(), DETAIL_USER_CODE_NOT_FOUND)

```

with:

```python
        )
        if claim is ScanClaim.CONFLICT_EXCHANGED and not await _recall(request, audit, code=code):
            return _Scanned(_recall_retry_response(), DETAIL_SCAN_CONFLICT)
        return _Scanned(_scan_conflict_response(), DETAIL_SCAN_CONFLICT)
    return _Scanned(_unpairable_response(), DETAIL_USER_CODE_NOT_FOUND)


async def _recall(request: Request, scan_audit: PairingAudit, *, code: DeviceCode) -> bool:
    """Recall the session a session swap produced, write its row, and say if it held.

    Spec section 7. Customer B scanned victim A's QR first and approved; A's
    AI client exchanged and holds a session for B's accounts; A's scan is this
    request. In order:

    1. RE-READ THE ROW. ``code`` was read before ``claim_scan``, possibly
       before the exchange, and ``session_id`` is written in the same
       compare-and-set as ``exchanged_at``.
    2. REVOKE THE FAMILY FIRST, so it cannot refresh into a ``jti`` step 3
       never names; ``revoke`` returns every live access ``jti``.
    3. LIST EACH ACCESS TOKEN on the ZT-7 store, which ``services/api``
       checks on every ``tools/call`` and ``tools/list``.

    The row names the family's customer (B), shares the scan row's
    ``call_id``, and is ``returned`` only when the family was revoked and
    every ``jti`` reached a shared store. Returns ``False`` when a step
    raised, and the caller answers a 503 the app retries at once; ``True``
    otherwise, including the rows that record nothing to recall. An audit
    write failure raises: a revocation that happened is the safe state, so
    nothing is withdrawn.
    """
    settings: ConfirmSettings = request.app.state.settings
    subject = code.scanned_by
    sid = ""
    detail: str | None = None
    held = True
    try:
        row = await request.app.state.device_code_store.get_device_code(code.device_code)
        if row is not None:
            subject = row.customer_ref or subject
            sid = row.session_id
        sessions: RefreshSessionStoreBase = request.app.state.refresh_session_store
        jtis = await sessions.revoke(sid, reason="recall") if sid else None
        if jtis is None:
            detail = DETAIL_RECALL_NO_SESSION
        else:
            await _reassert(revocation_store(request), jtis)
            if request.app.state.process_local_sessions:
                detail = DETAIL_RECALL_LOCAL_ONLY
    except Exception as exc:  # noqa: BLE001 -- recorded and answered 503; the app retries
        detail = type(exc).__name__
        held = False
        logger.error(
            "device scan: recalling the session of pairing %s failed with %s; the session "
            "may still be live",
            device_code_handle(code.device_code),
            detail,
        )
    recall = PairingAudit(
        db=request.app.state.postern_database,
        call_id=scan_audit.call_id,
        at=datetime.now(UTC),
        started=time.monotonic(),
        subject=subject,
        claims={},
        client_ip_value=pairing_client_ip(request, settings.trusted_proxy_hops),
        tool_name=RECALL_TOOL_NAME,
        route=SCAN_ROUTE,
    )
    recall.names(
        device_code=code.device_code, session_id=sid or None, paired_client_id=code.client_id
    )
    if detail is None:
        await recall.recalled()
    else:
        await recall.refused(detail)
    return held

```

In `services/confirm/main.py`, replace:

```python

def _refuse_process_local_sessions(settings: ConfirmSettings) -> None:
    """Refuse to start the device grant on per-process state, unless told to.
```

with:

```python

def _refuse_process_local_sessions(settings: ConfirmSettings) -> bool:
    """Refuse to start the device grant on per-process state, unless told to.
```

In `services/confirm/main.py`, replace:

```python
    deployment-wide contract not met.
    """
    if redis_url_from_env():
        return
    if settings.allow_process_local_sessions:
```

with:

```python
    deployment-wide contract not met.

    Returns whether sessions are process local, which a recall records.
    """
    if redis_url_from_env():
        return False
    if settings.allow_process_local_sessions:
```

Amended 1 October 2026: Task 5's review follow-ups changed the condition twice, first to
`os.environ.get("POSTERN_REDIS_URL", "").strip()` and then to the one reader
`postern_core.config.redis_url_from_env()`, so the old and new text above name that call.

In `services/confirm/main.py`, replace:

```python
        )
        return
    raise RuntimeError(
```

with:

```python
        )
        return True
    raise RuntimeError(
```

In `services/confirm/main.py`, replace:

```python
    # another replica or recalled at all.
    _refuse_process_local_sessions(settings)
    # The issuer and audience of every access token, refused here rather than
```

with:

```python
    # another replica or recalled at all.
    process_local_sessions = _refuse_process_local_sessions(settings)
    # The issuer and audience of every access token, refused here rather than
```

In `services/confirm/main.py`, replace:

```python
    app.state.refresh_session_store = refresh_session_store
    # Expose database for the approval callback.
```

with:

```python
    app.state.refresh_session_store = refresh_session_store
    # Read by a recall at `POST /scan`, which records `recall_local_only` when
    # the stores it wrote are this process's own.
    app.state.process_local_sessions = process_local_sessions
    # Expose database for the approval callback.
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `uv run pytest tests/test_scan.py tests/test_scan_recall.py -q`

Expected: 43 passed

- [ ] **Step 5: Format, then run the gate**

Run: `uv run ruff format packages services tests && make ci`

Expected: exit 0 (3717 passed at validation).

- [ ] **Step 6: Commit**

```bash
git add packages/postern-core/src/postern_core/auth/device_codes.py services/confirm/audit.py services/confirm/device_auth.py services/confirm/main.py tests/test_scan.py tests/test_scan_recall.py
git commit -m "feat(confirm): recall a swapped session at POST /scan" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 9: The read key leaves `services/confirm`

Spec section 1: the `choose_key_source(role="READ (device grant)", ...)` call, `read_minter`, `app.state.read_minter` and `app.state.postern_read_key_source` are removed from `create_confirm_app`, and `read_key_pem_path`, `read_key_kid`, `read_token_issuer` and `vault_read_key_name` from `ConfirmSettings`. The four read variables become `("api",)` in the inventory, so a confirm environment still setting one is warned, not refused. No process now holds READ and WRITE together.

**Files:**
- Modify: `packages/postern-core/src/postern_core/auth/keys.py` (`warn_ephemeral_signing_key` and `choose_key_source` docstrings)
- Modify: `packages/postern-core/src/postern_core/env_inventory.py` (four read rows)
- Modify: `services/confirm/main.py` (module docstring, imports, `create_confirm_app`)
- Modify: `services/confirm/settings.py` (module docstring, the Vault comment, four fields and their reads)
- Modify: `tests/test_confirm_service.py` (`test_the_confirm_settings_have_no_read_key_field`, `test_the_api_settings_name_no_session_key`)
- Modify: `tests/test_ephemeral_key_warning.py`
- Modify: `tests/test_settings_bounds.py`
- Modify: `tests/test_vault_live.py`

- [ ] **Step 1: Write the failing tests**

In `tests/test_confirm_service.py`, replace:

```python

    The only ``read_*`` fields are for the device-grant exception
    (both read and write keys needed to mint tokens atomically).

    ``vault_read_key_name`` JOINED THAT LIST ON 29 SEPTEMBER 2026 and is the
    same exception in the same place: the transit key whose name it carries is
    the one this service asks Vault to sign the browser's read token with,
    during the one atomic step that also mints the write token. Adding it here
    is a widening, so it is worth saying what did NOT widen -- the api
    service's settings gained `vault_read_key_name` and nothing named a write
    key, `postern_core.auth.vault.VaultSettings` names no key at all, and
    `postern_core.auth.keys.choose_key_source` takes one key and returns one
    source. The list below is a list of FIELDS; what stops a read process
    signing a payment is the Vault policy on the token each service holds,
    measured in `tests/test_vault_live.py`.
    """
```

with:

```python

    Until the layer-1 session token four ``read_*`` fields were allowed here,
    the device-grant exception: ``POST /token`` minted the browser a read
    token. It issues a session token signed by the SESSION key now, so the
    allowed set is empty and no process holds READ and WRITE together. What
    stops a process signing with a key it does not name is still the Vault
    policy on its token, measured in `tests/test_vault_live.py`.
    """
```

In `tests/test_confirm_service.py`, replace:

```python
    names = {f.name for f in dataclasses.fields(ConfirmSettings)}
    allowed_read_fields = {
        "read_key_pem_path",
        "read_key_kid",
        "read_token_issuer",
        "vault_read_key_name",
    }
    read_fields = {n for n in names if "read" in n}
    extra = read_fields - allowed_read_fields
    assert not extra, f"Unexpected read fields: {extra}"

```

with:

```python
    names = {f.name for f in dataclasses.fields(ConfirmSettings)}
    read_fields = {n for n in names if "read" in n}
    assert read_fields == set(), f"Unexpected read fields: {read_fields}"

```

In `tests/test_confirm_service.py`, replace:

```python

def test_a_write_token_is_rejected_by_the_read_key_set(settings: ConfirmSettings) -> None:
```

with:

```python

def test_the_api_settings_name_no_session_key() -> None:
    """The api verifies session tokens and never signs one.

    ``services/api`` reads the session key's PUBLIC half from confirm's
    ``/session/jwks.json`` through ``POSTERN_JWKS_URI``; a settings field
    naming the session key itself would be the first step to holding it.
    """
    import dataclasses

    from services.api.settings import Settings

    assert {f.name for f in dataclasses.fields(Settings) if "session_key" in f.name} == set()


def test_a_write_token_is_rejected_by_the_read_key_set(settings: ConfirmSettings) -> None:
```

In `tests/test_ephemeral_key_warning.py`, replace:

```python
        write_key_pem_path=_private_pem(tmp_path, "write.pem", "write-1"),
        read_key_pem_path=_private_pem(tmp_path, "read.pem", "read-1"),
        session_key_pem_path=_private_pem(tmp_path, "session.pem", "session-1"),
```

with:

```python
        write_key_pem_path=_private_pem(tmp_path, "write.pem", "write-1"),
        session_key_pem_path=_private_pem(tmp_path, "session.pem", "session-1"),
```

In `tests/test_ephemeral_key_warning.py`, replace:

```python
            ),
            3,  # write + read (device grant exception) + session
            id="confirm",
```

with:

```python
            ),
            2,  # write + session; no read key since the layer-1 session token
            id="confirm",
```

In `tests/test_ephemeral_key_warning.py`, replace:

```python
        assert "POSTERN_READ_KEY_PEM_PATH" in messages[0]
    # The confirm service has warnings for the write, read and session keys.
    if expected_count == 3:
        write_msg = [m for m in messages if "POSTERN_WRITE_KEY_PEM_PATH" in m]
```

with:

```python
        assert "POSTERN_READ_KEY_PEM_PATH" in messages[0]
    # The confirm service has warnings for the write and session keys.
    if expected_count == 2:
        write_msg = [m for m in messages if "POSTERN_WRITE_KEY_PEM_PATH" in m]
```

In `tests/test_ephemeral_key_warning.py`, replace:

```python
        assert len(write_msg) == 1
        assert len(read_msg) == 1
        assert len(session_msg) == 1
```

with:

```python
        assert len(write_msg) == 1
        assert read_msg == []
        assert len(session_msg) == 1
```

In `tests/test_settings_bounds.py`, replace:

```python
        assert len(names_read_by("api")) == 38
        assert len(names_read_by("confirm")) == 67
        assert len(names_read_by("migrations")) == 3
```

with:

```python
        assert len(names_read_by("api")) == 38
        assert len(names_read_by("confirm")) == 63
        assert len(names_read_by("migrations")) == 3
```

In `tests/test_vault_live.py`, replace:

```python
            vault_write_key_name=WRITE_KEY,
            vault_read_key_name=READ_KEY,
        )
```

with:

```python
            vault_write_key_name=WRITE_KEY,
        )
```

- [ ] **Step 2: Run them to verify they fail**

Run: `uv run pytest tests/test_confirm_service.py tests/test_ephemeral_key_warning.py tests/test_settings_bounds.py tests/test_vault_live.py -q`

Expected: FAIL, `4 failed, 412 passed`. The first failure reads `AssertionError: Unexpected read fields: {'read_key_pem_path', 'vault_read_key_name', 'read_token_issuer', 'read_key_kid'}`.

- [ ] **Step 3: Implement**

In `packages/postern-core/src/postern_core/auth/keys.py`, replace:

```python
    key already constructed. `services/api/main.py::_read_key_source`,
    `services/confirm/minter.py::_write_key_source` and
    `services/confirm/main.py::create_confirm_app` all reach it through that
    one function now, so a fourth key added anywhere gets this warning without
    anyone remembering to add it -- which is most of why the three copies were
    worth collapsing.
```

with:

```python
    key already constructed. `services/api/main.py::_read_key_source`,
    `services/confirm/minter.py::_write_key_source` and the session key's
    ``build_session_minter`` in `services/confirm/session_token.py` all reach it
    through that one function now, so a key added anywhere gets this warning
    without anyone remembering to add it -- which is most of why the copies were
    worth collapsing.
```

In `packages/postern-core/src/postern_core/auth/keys.py`, replace:

```python
    Three call sites, one per key: `services/api/main.py`'s READ key,
    `services/confirm/minter.py`'s WRITE key, and `services/confirm/main.py`'s
    READ key for the device grant. Each passes its own key's configuration and
    gets back one source. It was three copies of an if/else until Vault landed
    and each would have grown a third branch; `postern_core/config.py`'s
    docstring carries the general form of the argument for why a decision both
```

with:

```python
    Three call sites, one per key: `services/api/main.py`'s READ key,
    `services/confirm/minter.py`'s WRITE key, and the SESSION key in
    `services/confirm/session_token.py`, which signs the layer-1 access token.
    Until the session token the third was a READ key for the device grant in
    `services/confirm/main.py`, and no process holds READ and WRITE together
    any more. Each passes its own key's configuration and gets back one source.
    It was three copies of an if/else until Vault landed and each would have
    grown a third branch; `postern_core/config.py`'s
    docstring carries the general form of the argument for why a decision both
```

In `packages/postern-core/src/postern_core/auth/keys.py`, replace:

```python
    Args:
        role: ``"READ"`` or ``"WRITE"``, for the ephemeral-key warning only.
        kid: The configured key id. Under Vault it is a PREFIX and the
```

with:

```python
    Args:
        role: ``"READ"``, ``"WRITE"`` or ``"SESSION"``, for the ephemeral-key
            warning only.
        kid: The configured key id. Under Vault it is a PREFIX and the
```

In `packages/postern-core/src/postern_core/env_inventory.py`, replace:

```python
    EnvVar("POSTERN_MAX_SCOPES_LENGTH", "number", ("confirm",)),
    EnvVar("POSTERN_READ_KEY_KID", "string", BOTH),
    EnvVar("POSTERN_READ_KEY_PEM_PATH", "string", BOTH),
    EnvVar("POSTERN_READ_TOKEN_ISSUER", "string", BOTH),
    EnvVar("POSTERN_REDIS_DEVICE_CODE_TTL", "number", BOTH),
```

with:

```python
    EnvVar("POSTERN_MAX_SCOPES_LENGTH", "number", ("confirm",)),
    # ("api",) ONLY SINCE THE LAYER-1 SESSION TOKEN, which took the read key
    # out of `services/confirm`. A confirm environment still setting one gets
    # the "set but not read" warning, not a refusal.
    EnvVar("POSTERN_READ_KEY_KID", "string", ("api",)),
    EnvVar("POSTERN_READ_KEY_PEM_PATH", "string", ("api",)),
    EnvVar("POSTERN_READ_TOKEN_ISSUER", "string", ("api",)),
    EnvVar("POSTERN_REDIS_DEVICE_CODE_TTL", "number", BOTH),
```

In `packages/postern-core/src/postern_core/env_inventory.py`, replace:

```python
    # process that cannot name the write key also holds no policy to sign with
    # it.
    EnvVar("POSTERN_VAULT_ADDR", "string", BOTH),
    EnvVar("POSTERN_VAULT_PUBLIC_KEY_TTL_SECONDS", "number", BOTH),
    EnvVar("POSTERN_VAULT_READ_KEY_NAME", "string", BOTH),
    EnvVar("POSTERN_VAULT_SESSION_KEY_NAME", "string", ("confirm",)),
```

with:

```python
    # process that cannot name the write key also holds no policy to sign with
    # it. The read key's name is read by `api` alone, and the session key's by
    # `confirm` alone, since the layer-1 session token.
    EnvVar("POSTERN_VAULT_ADDR", "string", BOTH),
    EnvVar("POSTERN_VAULT_PUBLIC_KEY_TTL_SECONDS", "number", BOTH),
    EnvVar("POSTERN_VAULT_READ_KEY_NAME", "string", ("api",)),
    EnvVar("POSTERN_VAULT_SESSION_KEY_NAME", "string", ("confirm",)),
```

In `services/confirm/main.py`, replace:

```python
   device codes, accept banking app approvals, and exchange device codes for
   a read token. The read key here is a controlled exception to the key-split
   architecture; the write key is NOT used on this path at all since audit
   finding C-01 removed the write token from the ``/token`` response.
3. Handle verification challenge approvals (§6.3, §8.3): receive approvals
```

with:

```python
   device codes, accept banking app approvals, and exchange device codes for
   a layer-1 session, signed by a third key (SESSION) published at
   ``/session/jwks.json``. This service holds no read key; the write key is
   NOT used on this path at all since audit finding C-01 removed the write
   token from the ``/token`` response.
3. Handle verification challenge approvals (§6.3, §8.3): receive approvals
```

In `services/confirm/main.py`, replace:

```python
from postern_core.auth.device_keys import DeviceKeyStoreBase, FileDeviceKeyStore
from postern_core.auth.internal_jwt import InternalTokenMinter
from postern_core.auth.keys import choose_key_source
from postern_core.auth.refresh_sessions import create_refresh_session_store
```

with:

```python
from postern_core.auth.device_keys import DeviceKeyStoreBase, FileDeviceKeyStore
from postern_core.auth.refresh_sessions import create_refresh_session_store
```

In `services/confirm/main.py`, replace:

```python

    Builds both read and write minters. The read key path is a controlled
    exception to the architecture's key-split rule — see ``ConfirmSettings``
    docstring.

```

with:

```python

    Builds the write and session minters and no read minter: no process
    holds READ and WRITE together (``ConfirmSettings``' docstring).

```

In `services/confirm/main.py`, replace:

```python
    session_minter, session_key_source = build_session_minter(settings)

    # --- Read key / minter (device grant exception) ---
    #
    # THE ONE PROCESS IN THIS REPOSITORY THAT HOLDS TWO KEYS, and it is a
    # recorded exception rather than a leak: the device grant mints the
    # browser's read token in the same atomic step as the write one, so this
    # service needs both. `services/confirm/settings.py`'s module docstring is
    # where that is argued. Note what it is NOT: two calls to the same
    # one-key-in, one-source-out function, which is all
    # `choose_key_source` can do. There is still no object anywhere that
    # hands a process both.
    read_key_source = choose_key_source(
        role="READ (device grant)",
        kid=settings.read_key_kid,
        vault=settings.vault,
        vault_key_name=settings.vault_read_key_name,
        pem_path=settings.read_key_pem_path,
        pem_env_var="POSTERN_READ_KEY_PEM_PATH",
    )
    read_minter = InternalTokenMinter(issuer=settings.read_token_issuer, key_source=read_key_source)

```

with:

```python
    session_minter, session_key_source = build_session_minter(settings)

```

In `services/confirm/main.py`, replace:

```python
    app.state.postern_session_key_source = session_key_source
    app.state.postern_read_key_source = read_key_source
    # Expose minters and store for the device auth routes.
    app.state.read_minter = read_minter
    app.state.write_minter = _write_minter
```

with:

```python
    app.state.postern_session_key_source = session_key_source
    # Expose minters and store for the device auth routes.
    app.state.write_minter = _write_minter
```

In `services/confirm/settings.py`, replace:

```python

The confirm service also needs a READ key to mint read tokens during device
code exchange (the browser receives the read token after the user approves).
This is a deliberate exception: the device grant flow mints both read and
write tokens in one atomic step, so it needs both keys. The separation is
preserved at startup — no code path hands one process both keys for general
use; the device grant is a controlled exception.

```

with:

```python

The confirm service holds NO READ KEY. Until the layer-1 session token it
held one, as a recorded exception, because ``POST /token`` minted the
browser a read token with it -- a layer-2 token the accounts backend accepts,
which handoff §7.1 keeps apart from layer 1. The device grant now issues a
session token signed by a third key, SESSION (the ``session_*`` fields
below), which signs nothing else and is published at ``/session/jwks.json``.
So no process holds READ and WRITE together: ``services/api`` holds READ,
this service holds WRITE and SESSION, and the device grant's read-key
exception is gone. ``tests/test_confirm_service.py`` pins the field list.

```

In `services/confirm/settings.py`, replace:

```python
    # VAULT TRANSIT. `vault` is the same six values `services/api/settings.py`
    # reads, from the same `vault_from_env`, because there is one Vault. The
    # two KEY NAMES are read here and not there, and this is the service that
    # has both -- the device grant exception this file's module docstring
    # already records. What keeps the split real under Vault is not this
    # dataclass: it is the policy on the Vault token each SERVICE holds. The
    # api service's token has `update` on `transit/sign/<read key>` and
    # nothing on the write key, so a compromised read process cannot sign a
    # payment token even knowing its name -- measured against Vault 1.20.4 in
    # `tests/test_vault_live.py`.
```

with:

```python
    # VAULT TRANSIT. `vault` is the same six values `services/api/settings.py`
    # reads, from the same `vault_from_env`, because there is one Vault. This
    # service names two transit keys, the write key here and the session key
    # below, and names no read key. What keeps the split real under Vault is
    # not this dataclass: it is the policy on the Vault token each SERVICE
    # holds. The api service's token has `update` on `transit/sign/<read key>`
    # and nothing on the write or session key, and this service's token has
    # nothing on the read key -- measured against Vault 1.20.4 in
    # `tests/test_vault_live.py`.
```

In `services/confirm/settings.py`, replace:

```python
    vault_write_key_name: str = "postern-write"
    vault_read_key_name: str = "postern-read"
    # Device authorization (§7.3): where the user goes to approve pairing.
```

with:

```python
    vault_write_key_name: str = "postern-write"
    # Device authorization (§7.3): where the user goes to approve pairing.
```

In `services/confirm/settings.py`, replace:

```python
    device_poll_interval_seconds: int = 5
    # Read key for device grant token exchange (both read + write needed here).
    read_key_pem_path: str | None = None
    read_key_kid: str = "read-1"
    read_token_issuer: str = "https://mcp-read.internal"  # noqa: S105
    # Approval callback (§6.3, §8.3): backend write endpoints + challenges DB.
```

with:

```python
    device_poll_interval_seconds: int = 5
    # Approval callback (§6.3, §8.3): backend write endpoints + challenges DB.
```

In `services/confirm/settings.py`, replace:

```python
            vault_write_key_name=os.environ.get("POSTERN_VAULT_WRITE_KEY_NAME", "postern-write"),
            vault_read_key_name=os.environ.get("POSTERN_VAULT_READ_KEY_NAME", "postern-read"),
            write_token_issuer=os.environ.get(
```

with:

```python
            vault_write_key_name=os.environ.get("POSTERN_VAULT_WRITE_KEY_NAME", "postern-write"),
            write_token_issuer=os.environ.get(
```

In `services/confirm/settings.py`, replace:

```python
                ),
            ),
            read_key_pem_path=os.environ.get("POSTERN_READ_KEY_PEM_PATH") or None,
            read_key_kid=os.environ.get("POSTERN_READ_KEY_KID", "read-1"),
            read_token_issuer=os.environ.get(
                "POSTERN_READ_TOKEN_ISSUER", "https://mcp-read.internal"
            ),
```

with:

```python
                ),
            ),
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `uv run pytest tests/test_confirm_service.py tests/test_ephemeral_key_warning.py tests/test_settings_bounds.py tests/test_vault_live.py -q`

Expected: 416 passed

- [ ] **Step 5: Format, then run the gate**

Run: `uv run ruff format packages services tests && make ci`

Expected: exit 0 (3718 passed at validation).

- [ ] **Step 6: Commit**

```bash
git add packages/postern-core/src/postern_core/auth/keys.py packages/postern-core/src/postern_core/env_inventory.py services/confirm/main.py services/confirm/settings.py tests/test_confirm_service.py tests/test_ephemeral_key_warning.py tests/test_settings_bounds.py tests/test_vault_live.py
git commit -m "refactor(confirm): take the read key out of the confirm service" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 10: `services/api` verifies session tokens with a bounded JWKS cache

Spec section 8: `SessionTokenVerifier` overrides the parent's private `_get_jwks_key` so the cache lives `POSTERN_VAULT_PUBLIC_KEY_TTL_SECONDS`, an unknown kid is fetched for at most once per 30 seconds and refused in between, and concurrent misses share one fetch; a failed fetch leaves the cache as it was. `build_server` builds it in place of `JWTVerifier` and refuses a non-URI `POSTERN_AUDIENCE` when a JWKS URI is set, unless `POSTERN_ALLOW_NON_URI_AUDIENCE` is. The TTL is read through a new `public_key_ttl_from_env` in `postern_core.auth.vault`, so the variable keeps one read site. Four api tests that build a production-shaped server gain a URI audience.

**Files:**
- Modify: `packages/postern-core/src/postern_core/auth/vault.py` (`public_key_ttl_from_env`, `vault_from_env`, `__all__`)
- Modify: `packages/postern-core/src/postern_core/env_inventory.py`
- Modify: `services/api/server.py` (imports, `logger`, `build_server`)
- Create: `services/api/session_verifier.py` (`MIN_REFETCH_INTERVAL_SECONDS`, `SessionTokenVerifier`)
- Modify: `services/api/settings.py` (`customer_jwks_ttl_seconds`, `allow_non_uri_audience`, their reads)
- Modify: `tests/test_asgi_app.py`
- Modify: `tests/test_ephemeral_key_warning.py`
- Create: `tests/test_session_verifier.py`
- Modify: `tests/test_settings_bounds.py`
- Modify: `tests/test_startup_minter_probe.py`

- [ ] **Step 1: Write the failing tests**

In `tests/test_asgi_app.py`, replace:

```python
    "POSTERN_TOKEN_ISSUER": "https://issuer.test",
}
```

with:

```python
    "POSTERN_TOKEN_ISSUER": "https://issuer.test",
    # A resource URI, which `build_server` requires once a JWKS URI is set.
    "POSTERN_AUDIENCE": "https://mcp.postern.test/mcp",
}
```

In `tests/test_asgi_app.py`, replace:

```python
        customer_token_issuer="https://issuer.test",  # noqa: S106
    )
```

with:

```python
        customer_token_issuer="https://issuer.test",  # noqa: S106
        audience="https://mcp.postern.test/mcp",
    )
```

In `tests/test_ephemeral_key_warning.py`, replace:

```python
        customer_token_issuer="https://issuer.test",  # noqa: S106
    )
```

with:

```python
        customer_token_issuer="https://issuer.test",  # noqa: S106
        audience="https://mcp.postern.test/mcp",
    )
```

Create `tests/test_session_verifier.py` with:

```python
"""``services/api``'s session-token verifier and its bounded JWKS cache (spec section 8).

Three layers. The private method this subclass overrides is pinned against
the installed FastMCP. The cache's rules are driven directly, with an
injected client counting fetches. And the whole thing is driven through the
assembled ``build_server`` app against a real HTTP JWKS server that counts
the requests it receives, because a signature pin does not prove the
override is called: if an upgrade stops routing through ``_get_jwks_key``,
the last test sees FastMCP's unbounded refetch and fails. Re-run it on every
``fastmcp`` version bump.
"""

from __future__ import annotations

import asyncio
import inspect
import json
import threading
import time
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import httpx2
import pytest
from fastmcp.server.auth.providers.jwt import JWTVerifier
from joserfc import jwt
from joserfc.jwk import KeySet, RSAKey

from services.api.server import build_server
from services.api.session_verifier import MIN_REFETCH_INTERVAL_SECONDS, SessionTokenVerifier
from services.api.settings import Settings
from tests.conftest import TEST_CUSTOMER

ISSUER = "https://auth.postern.test"
AUDIENCE = "https://mcp.postern.test/mcp"
JWKS_URI = "https://auth.postern.test/session/jwks.json"


def _key(kid: str) -> RSAKey:
    return RSAKey.generate_key(2048, parameters={"kid": kid, "use": "sig", "alg": "RS256"})


def _jwks(*keys: RSAKey) -> dict[str, Any]:
    return dict(KeySet(list(keys)).as_dict(private=False))


def _token(key: RSAKey, *, kid: str | None = None) -> str:
    now = int(time.time())
    claims = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": "cust_7f3a",
        "client_id": "claude-code",
        "jti": f"j-{now}",
        "iat": now,
        "exp": now + 600,
    }
    return jwt.encode({"alg": "RS256", "kid": kid or str(key.kid)}, claims, key)


class CountingJwks:
    """An httpx2 handler that serves a mutable key set and counts requests."""

    def __init__(self, jwks: dict[str, Any], *, delay: float = 0.0, fail: bool = False) -> None:
        self.jwks = jwks
        self.delay = delay
        self.fail = fail
        self.fetches = 0

    async def __call__(self, request: httpx2.Request) -> httpx2.Response:
        self.fetches += 1
        if self.delay:
            await asyncio.sleep(self.delay)
        if self.fail:
            return httpx2.Response(503, json={})
        return httpx2.Response(200, json=self.jwks)


def _verifier(handler: CountingJwks, *, ttl: float = 300.0) -> SessionTokenVerifier:
    return SessionTokenVerifier(
        jwks_uri=JWKS_URI,
        issuer=ISSUER,
        audience=AUDIENCE,
        required_scopes=None,
        cache_ttl_seconds=ttl,
        http_client=httpx2.AsyncClient(transport=httpx2.MockTransport(handler)),
    )


class Clock:
    """``time.time`` moved by hand, for both this subclass and its parent."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.now = time.time()
        monkeypatch.setattr(time, "time", lambda: self.now)

    def advance(self, seconds: float) -> None:
        self.now += seconds


class TestThePinnedParent:
    def test_the_overridden_private_method_keeps_its_signature(self) -> None:
        """The annotations are strings because the parent module uses
        ``from __future__ import annotations``; measured against fastmcp 4.0.3."""
        signature = str(inspect.signature(JWTVerifier._get_jwks_key))
        assert signature == "(self, kid: 'str | None') -> 'str'"

    def test_the_parent_caches_for_an_hour_which_is_why_this_exists(self) -> None:
        parent = JWTVerifier(jwks_uri=JWKS_URI, issuer=ISSUER, audience=AUDIENCE)
        assert parent._cache_ttl == 3600


class TestTheCache:
    async def test_a_published_key_verifies_with_one_fetch(self) -> None:
        key = _key("session-1.v1")
        handler = CountingJwks(_jwks(key))
        verifier = _verifier(handler)
        for _ in range(5):
            assert await verifier.verify_token(_token(key)) is not None
        assert handler.fetches == 1

    async def test_a_burst_with_one_unknown_kid_fetches_once_per_floor(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        clock = Clock(monkeypatch)
        key, stranger = _key("session-1.v1"), _key("forged-1")
        handler = CountingJwks(_jwks(key))
        verifier = _verifier(handler)
        for _ in range(20):
            assert await verifier.verify_token(_token(stranger)) is None
        assert handler.fetches == 1
        clock.advance(MIN_REFETCH_INTERVAL_SECONDS - 1)
        assert await verifier.verify_token(_token(stranger)) is None
        assert handler.fetches == 1
        clock.advance(2)
        assert await verifier.verify_token(_token(stranger)) is None
        assert handler.fetches == 2
        assert MIN_REFETCH_INTERVAL_SECONDS == 30.0

    async def test_concurrent_misses_share_one_fetch(self) -> None:
        key, stranger = _key("session-1.v1"), _key("forged-1")
        handler = CountingJwks(_jwks(key), delay=0.05)
        verifier = _verifier(handler)
        results = await asyncio.gather(
            *(verifier.verify_token(_token(stranger)) for _ in range(5)),
            *(verifier.verify_token(_token(key)) for _ in range(5)),
        )
        assert handler.fetches == 1
        assert [r is None for r in results] == [True] * 5 + [False] * 5

    async def test_a_removed_key_stops_verifying_within_the_ttl(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        clock = Clock(monkeypatch)
        old, new = _key("session-1.v1"), _key("session-1.v2")
        handler = CountingJwks(_jwks(old, new))
        verifier = _verifier(handler, ttl=300.0)
        assert await verifier.verify_token(_token(old)) is not None
        handler.jwks = _jwks(new)
        clock.advance(299)
        assert await verifier.verify_token(_token(old)) is not None, "inside the TTL"
        clock.advance(2)
        assert await verifier.verify_token(_token(old)) is None
        assert await verifier.verify_token(_token(new)) is not None

    async def test_a_failing_endpoint_is_asked_once_per_floor_and_the_cache_survives(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        clock = Clock(monkeypatch)
        key, stranger = _key("session-1.v1"), _key("forged-1")
        handler = CountingJwks(_jwks(key))
        verifier = _verifier(handler)
        assert await verifier.verify_token(_token(key)) is not None
        handler.fail = True
        clock.advance(MIN_REFETCH_INTERVAL_SECONDS + 1)
        for _ in range(10):
            assert await verifier.verify_token(_token(stranger)) is None
        assert handler.fetches == 2
        assert await verifier.verify_token(_token(key)) is not None, "the fresh cache survived"


class TestTheSettings:
    def test_the_ttl_is_read_without_a_vault(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("POSTERN_BACKEND_BASE_URL", "https://backend.test")
        monkeypatch.delenv("POSTERN_VAULT_ADDR", raising=False)
        monkeypatch.setenv("POSTERN_VAULT_PUBLIC_KEY_TTL_SECONDS", "42")
        settings = Settings.from_env()
        assert settings.vault is None
        assert settings.customer_jwks_ttl_seconds == 42.0

    def test_build_server_builds_the_bounded_verifier(self) -> None:
        settings = Settings(
            backend_base_url="https://backend.test",
            customer_jwks_uri=JWKS_URI,
            customer_token_issuer=ISSUER,
            audience=AUDIENCE,
            customer_jwks_ttl_seconds=42.0,
        )
        server = build_server(settings, resolver=lambda: TEST_CUSTOMER, backend=None)
        assert isinstance(server.auth, SessionTokenVerifier)
        assert server.auth._session_ttl == 42.0

    @pytest.mark.parametrize(
        "audience", ["postern", "https://mcp.postern.test", "https://MCP.postern.test/mcp"]
    )
    def test_a_non_uri_audience_refuses_to_start(self, audience: str) -> None:
        settings = Settings(
            backend_base_url="https://backend.test",
            customer_jwks_uri=JWKS_URI,
            customer_token_issuer=ISSUER,
            audience=audience,
        )
        with pytest.raises(ValueError, match="POSTERN_ALLOW_NON_URI_AUDIENCE"):
            build_server(settings, resolver=lambda: TEST_CUSTOMER, backend=None)

    def test_the_flag_admits_it_and_warns(self, caplog: pytest.LogCaptureFixture) -> None:
        settings = Settings(
            backend_base_url="https://backend.test",
            customer_jwks_uri=JWKS_URI,
            customer_token_issuer=ISSUER,
            allow_non_uri_audience=True,
        )
        build_server(settings, resolver=lambda: TEST_CUSTOMER, backend=None)
        assert "POSTERN_ALLOW_NON_URI_AUDIENCE is set" in caplog.text

    def test_no_customer_authentication_needs_no_uri(self) -> None:
        build_server(Settings.for_testing(), resolver=lambda: TEST_CUSTOMER, backend=None)

    def test_the_flag_is_read_from_the_environment(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("POSTERN_BACKEND_BASE_URL", "https://backend.test")
        monkeypatch.setenv("POSTERN_ALLOW_NON_URI_AUDIENCE", "true")
        assert Settings.from_env().allow_non_uri_audience is True


class _Served:
    """A real HTTP JWKS endpoint on 127.0.0.1 that publishes ``key`` and counts GETs."""

    def __init__(self, key: RSAKey) -> None:
        self.key = key
        self.jwks = _jwks(key)
        self.fetches = 0
        served = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802 -- the stdlib's name
                served.fetches += 1
                body = json.dumps(served.jwks).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args: Any) -> None:
                return None

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}/session/jwks.json"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)


@pytest.fixture()
def served() -> Iterator[_Served]:
    endpoint = _Served(_key("session-1.v1"))
    endpoint.thread.start()
    yield endpoint
    endpoint.server.shutdown()
    endpoint.server.server_close()


async def _tools_list(app: Any, token: str) -> httpx2.Response:
    async with httpx2.AsyncClient(
        transport=httpx2.ASGITransport(app=app), base_url="http://api.test"
    ) as client:
        return await client.post(
            "/mcp",
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/json, text/event-stream",
                "Mcp-Method": "tools/list",
                "MCP-Protocol-Version": "2026-07-28",
            },
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/list",
                "params": {
                    "_meta": {
                        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                        "io.modelcontextprotocol/clientCapabilities": {},
                    }
                },
            },
        )


async def test_the_assembled_app_fetches_only_what_the_override_allows(served: _Served) -> None:
    settings = Settings(
        backend_base_url="https://backend.test",
        customer_jwks_uri=served.url,
        customer_token_issuer=ISSUER,
        audience=AUDIENCE,
    )
    server = build_server(settings, resolver=lambda: TEST_CUSTOMER, backend=None)
    app = server.http_app(path="/mcp")
    stranger = _key("forged-1")

    async with app.router.lifespan_context(app):
        first = await _tools_list(app, _token(stranger))
        second = await _tools_list(app, _token(stranger))
        genuine = await _tools_list(app, _token(served.key))

    assert first.status_code == 401
    assert second.status_code == 401
    assert served.fetches == 1, "the second miss inside 30 seconds fetched again"
    assert genuine.status_code == 200, genuine.text
    assert served.fetches == 1, "a published kid on a fresh cache fetched again"
```

In `tests/test_settings_bounds.py`, replace:

```python
        assert len(BOUNDED_NAMES | STORE_BOUNDED_NAMES | VAULT_BOUNDED_NAMES | FLAGS) == 51
        assert len(names_read_by("api")) == 38
        assert len(names_read_by("confirm")) == 63
```

with:

```python
        assert len(BOUNDED_NAMES | STORE_BOUNDED_NAMES | VAULT_BOUNDED_NAMES | FLAGS) == 51
        assert len(names_read_by("api")) == 39
        assert len(names_read_by("confirm")) == 63
```

In `tests/test_startup_minter_probe.py`, replace:

```python
            customer_token_issuer="https://issuer.test",  # noqa: S106
        ),
```

with:

```python
            customer_token_issuer="https://issuer.test",  # noqa: S106
            audience="https://mcp.postern.test/mcp",
        ),
```

- [ ] **Step 2: Run them to verify they fail**

Run: `uv run pytest tests/test_asgi_app.py tests/test_ephemeral_key_warning.py tests/test_session_verifier.py tests/test_settings_bounds.py tests/test_startup_minter_probe.py -q`

Expected: FAIL, `1 error`. The first failure reads `ModuleNotFoundError: No module named 'services.api.session_verifier'`.

- [ ] **Step 3: Implement**

In `packages/postern-core/src/postern_core/auth/vault.py`, replace:

```python
    "VaultTransitKeySource",
    "vault_from_env",
```

with:

```python
    "VaultTransitKeySource",
    "public_key_ttl_from_env",
    "vault_from_env",
```

In `packages/postern-core/src/postern_core/auth/vault.py`, replace:

```python
        ),
        public_key_ttl_seconds=float_from_env(
            "POSTERN_VAULT_PUBLIC_KEY_TTL_SECONDS",
            DEFAULT_PUBLIC_KEY_TTL_SECONDS,
            minimum=0,
            exclusive=True,
            because=(
                "It is how long a transit key read is reused before Vault is asked again; "
                "at zero every signature costs a second round trip to re-read a public key "
                "that changes only when an operator rotates it."
            ),
        ),
```

with:

```python
        ),
        public_key_ttl_seconds=public_key_ttl_from_env(),
    )


def public_key_ttl_from_env() -> float:
    """``POSTERN_VAULT_PUBLIC_KEY_TTL_SECONDS``, read in one place for two readers.

    `vault_from_env` above, for how long a transit key read is reused, and
    ``services/api``'s settings, for how long its session-token verifier
    trusts confirm's ``/session/jwks.json`` -- read whether or not a Vault is
    configured, because the session key rotates the same way under a PEM.
    """
    return float_from_env(
        "POSTERN_VAULT_PUBLIC_KEY_TTL_SECONDS",
        DEFAULT_PUBLIC_KEY_TTL_SECONDS,
        minimum=0,
        exclusive=True,
        because=(
            "It is how long a transit key read is reused before Vault is asked again; "
            "at zero every signature costs a second round trip to re-read a public key "
            "that changes only when an operator rotates it."
        ),
```

In `packages/postern-core/src/postern_core/env_inventory.py`, replace:

```python
    EnvVar(REQUIRED_ENV, "string", EVERYWHERE),
    EnvVar("POSTERN_ALLOW_NON_URI_AUDIENCE", "flag", ("confirm",)),
    EnvVar("POSTERN_ALLOW_PROCESS_LOCAL_SESSIONS", "flag", ("confirm",)),
```

with:

```python
    EnvVar(REQUIRED_ENV, "string", EVERYWHERE),
    EnvVar("POSTERN_ALLOW_NON_URI_AUDIENCE", "flag", BOTH),
    EnvVar("POSTERN_ALLOW_PROCESS_LOCAL_SESSIONS", "flag", ("confirm",)),
```

In `services/api/server.py`, replace:

```python

from collections.abc import Awaitable, Callable, Sequence
```

with:

```python

import logging
from collections.abc import Awaitable, Callable, Sequence
```

In `services/api/server.py`, replace:

```python
from mcp.types import ToolAnnotations
from postern_core.facade.protocol import BackendReader
```

with:

```python
from mcp.types import ToolAnnotations
from postern_core.auth.resource_uri import is_normal_https_resource
from postern_core.facade.protocol import BackendReader
```

In `services/api/server.py`, replace:

```python
from services.api.consent import consent_for
from services.api.settings import Settings
from services.api.tools import BUILTIN_READ_MODULES

```

with:

```python
from services.api.consent import consent_for
from services.api.session_verifier import SessionTokenVerifier
from services.api.settings import Settings
from services.api.tools import BUILTIN_READ_MODULES

logger = logging.getLogger(__name__)

```

In `services/api/server.py`, replace:

```python

    auth: AuthProvider | None = None
    if has_jwks_uri and has_issuer:
        auth = JWTVerifier(
            jwks_uri=settings.customer_jwks_uri,
```

with:

```python

    if has_jwks_uri and not is_normal_https_resource(settings.audience):
        # THE AUDIENCE MUST BE THE MCP SERVER'S RESOURCE URI. RFC 8707 section
        # 2 requires an absolute URI, and confirm stamps exactly this string
        # as `aud` on every session token, so the default `postern` stops
        # working in any deployment with customer authentication. That is the
        # point, and the local stack sets a URI rather than the flag.
        if not settings.allow_non_uri_audience:
            raise ValueError(
                f"POSTERN_AUDIENCE ({settings.audience!r}) must be the MCP server's "
                "resource URI: an absolute https URI with a host, a lower-case scheme and "
                "host, no default port and a non-empty path (RFC 8707 section 2), equal "
                "to services/confirm's POSTERN_SESSION_TOKEN_AUDIENCE. Set "
                "POSTERN_ALLOW_NON_URI_AUDIENCE for a local stack."
            )
        logger.warning(
            "POSTERN_ALLOW_NON_URI_AUDIENCE is set: this server accepts access tokens for "
            "the audience %r, which is not an absolute https URI. No deployment may run "
            "this way.",
            settings.audience,
        )

    auth: AuthProvider | None = None
    if has_jwks_uri and has_issuer:
        # A `JWTVerifier` whose JWKS cache is bounded: its TTL is the public
        # key TTL, unknown kids are fetched at most once per 30 seconds, and
        # concurrent misses share one fetch (`services/api/session_verifier.py`).
        # Still a `JWTVerifier` in every other respect: signature, `exp`,
        # `iss` and `aud` are the parent's checks, unchanged.
        verifier: JWTVerifier = SessionTokenVerifier(
            jwks_uri=settings.customer_jwks_uri,
```

In `services/api/server.py`, replace:

```python
            required_scopes=None,
        )
    if auth_override is not None:
```

with:

```python
            required_scopes=None,
            cache_ttl_seconds=settings.customer_jwks_ttl_seconds,
        )
        auth = verifier
    if auth_override is not None:
```

Create `services/api/session_verifier.py` with:

```python
"""The api's verifier for layer-1 session tokens, with a JWKS cache that is bounded.

``services/api`` accepts the access tokens ``services/confirm`` issues at
``POST /token``: signed by the SESSION key and published at confirm's
``/session/jwks.json``, which this service fetches from ``POSTERN_JWKS_URI``.
FastMCP 4.0.3's ``JWTVerifier`` already checks the signature against the key
the token's ``kid`` names, ``exp``, ``iss`` and ``aud``; what it does not do
is bound its JWKS fetches.

WHAT THE PARENT DOES, read in the installed ``fastmcp/server/auth/providers/jwt.py``
rather than recalled: its constructor sets a one-hour cache TTL, and its
``_get_jwks_key`` serves from the cache only while the cache is younger than
that AND the ``kid`` is in it. Any other case fetches, with a fresh
``httpx2.AsyncClient`` unless one was injected. There is no floor on refetches
and no negative cache, so every token carrying an unseen ``kid`` causes one
outbound fetch -- an unauthenticated caller can drive them at the api's full
request rate -- and a key removed from the published set stays trusted for up
to an hour.

WHAT THIS CHANGES, and nothing else:

- the cache lives ``cache_ttl_seconds`` (``POSTERN_VAULT_PUBLIC_KEY_TTL_SECONDS``,
  300 by default), so a removed key stops verifying within that;
- a ``kid`` the cache has never held is fetched for at most once per
  `MIN_REFETCH_INTERVAL_SECONDS`, and refused without a fetch in between: the
  negative cache;
- one fetch at a time, under an ``asyncio.Lock``, and callers that waited on
  it read its result instead of fetching again;
- a fetch that FAILS leaves the cache as it was and holds every further fetch
  to the same floor, so an unreachable JWKS endpoint is asked at most once per
  interval rather than once per request.

IT OVERRIDES A PRIVATE METHOD of a pinned dependency (``fastmcp>=4.0.3,<5``).
``tests/test_session_verifier.py`` pins the parent's signature and drives a
counting JWKS server through the assembled app, because a signature that
still matches does not prove the override is still called. Re-run that test,
not only keep it green, on every ``fastmcp`` version bump.

PER PROCESS. The floor and the coalescing live on one object, so "one fetch per
30 seconds on a miss plus one per TTL" is per api worker process; the
Dockerfile's ``api`` target runs one uvicorn worker per container today.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

from fastmcp.server.auth.providers.jwt import JWTVerifier

#: The floor under fetches for a ``kid`` the cache has never held, in seconds.
MIN_REFETCH_INTERVAL_SECONDS = 30.0


class SessionTokenVerifier(JWTVerifier):
    """``JWTVerifier`` with a bounded JWKS cache; see the module docstring."""

    def __init__(
        self,
        *,
        cache_ttl_seconds: float,
        min_refetch_interval_seconds: float = MIN_REFETCH_INTERVAL_SECONDS,
        **kwargs: Any,
    ) -> None:
        super().__init__(**kwargs)
        self._session_ttl = cache_ttl_seconds
        self._refetch_floor = min_refetch_interval_seconds
        self._last_fetch = float("-inf")
        self._last_fetch_failed = False
        self._fetch_lock = asyncio.Lock()

    def _cached(self, kid: str | None, now: float) -> str | None:
        """The cached key for ``kid`` while the cache is fresh, else ``None``."""
        if now - self._jwks_cache_time >= self._session_ttl:
            return None
        if kid:
            return self._jwks_cache.get(kid)
        if len(self._jwks_cache) == 1:
            return next(iter(self._jwks_cache.values()))
        return None

    def _known(self, kid: str | None) -> bool:
        """Whether the last fetch published ``kid``, however long ago."""
        if kid:
            return kid in self._jwks_cache
        return len(self._jwks_cache) == 1

    async def _get_jwks_key(self, kid: str | None) -> str:
        key = self._cached(kid, time.time())
        if key is not None:
            return key
        async with self._fetch_lock:
            now = time.time()
            # A caller that waited on the lock reads what the fetch it waited
            # for found, instead of fetching again.
            key = self._cached(kid, now)
            if key is not None:
                return key
            too_soon = now - self._last_fetch < self._refetch_floor
            if too_soon and (self._last_fetch_failed or not self._known(kid)):
                # THE NEGATIVE CACHE: this kid was not published at the last
                # fetch, or that fetch failed, and it is too recent to repeat.
                raise ValueError(f"Key ID {kid!r} not found in JWKS")
            self._last_fetch = now
            previous = self._jwks_cache_time
            # Force the parent past its own cache check, whose TTL is an hour:
            # this method has already decided a fetch is owed. The parent
            # stamps the cache time only after a fetch that succeeded.
            self._jwks_cache_time = 0
            try:
                return await super()._get_jwks_key(kid)
            finally:
                self._last_fetch_failed = self._jwks_cache_time == 0
                if self._last_fetch_failed:
                    self._jwks_cache_time = previous
```

In `services/api/settings.py`, replace:

```python

from postern_core.auth.vault import VaultSettings, vault_from_env
from postern_core.config import bool_from_env, float_from_env, int_from_env
```

with:

```python

from postern_core.auth.vault import (
    DEFAULT_PUBLIC_KEY_TTL_SECONDS,
    VaultSettings,
    public_key_ttl_from_env,
    vault_from_env,
)
from postern_core.config import bool_from_env, float_from_env, int_from_env
```

In `services/api/settings.py`, replace:

```python
    audience: str = "postern"
    strict_headers: bool = False
```

with:

```python
    audience: str = "postern"
    # How long the session-token verifier trusts the key set it fetched from
    # `customer_jwks_uri`, from POSTERN_VAULT_PUBLIC_KEY_TTL_SECONDS whether
    # or not a Vault is configured. `services/api/session_verifier.py` says
    # why a removed key must stop verifying within this.
    customer_jwks_ttl_seconds: float = DEFAULT_PUBLIC_KEY_TTL_SECONDS
    # The local-stack escape from the audience refusal in
    # `services/api/server.py`'s `build_server`: RFC 8707 section 2 requires an
    # absolute URI, and the default above is not one.
    allow_non_uri_audience: bool = False
    strict_headers: bool = False
```

In `services/api/settings.py`, replace:

```python
            audience=os.environ.get("POSTERN_AUDIENCE", "postern"),
            # WAS ``== "1"`` UNTIL 2026-09-26, so
```

with:

```python
            audience=os.environ.get("POSTERN_AUDIENCE", "postern"),
            customer_jwks_ttl_seconds=public_key_ttl_from_env(),
            allow_non_uri_audience=bool_from_env(
                "POSTERN_ALLOW_NON_URI_AUDIENCE",
                False,
                because=(
                    "It lets a local stack run with an access-token audience that is not "
                    "an absolute https URI, which RFC 8707 section 2 requires."
                ),
            ),
            # WAS ``== "1"`` UNTIL 2026-09-26, so
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `uv run pytest tests/test_asgi_app.py tests/test_ephemeral_key_warning.py tests/test_session_verifier.py tests/test_settings_bounds.py tests/test_startup_minter_probe.py -q`

Expected: 438 passed

- [ ] **Step 5: Format, then run the gate**

Run: `uv run ruff format packages services tests && make ci`

Expected: exit 0 (3734 passed at validation).

- [ ] **Step 6: Commit**

```bash
git add packages/postern-core/src/postern_core/auth/vault.py packages/postern-core/src/postern_core/env_inventory.py services/api/server.py services/api/session_verifier.py services/api/settings.py tests/test_asgi_app.py tests/test_ephemeral_key_warning.py tests/test_session_verifier.py tests/test_settings_bounds.py tests/test_startup_minter_probe.py
git commit -m "feat(api): verify session tokens with a bounded JWKS cache" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 11: The local stack and the live Vault

Spec sections 2 ("Vault"), 4 ("a `redis` service") and 8 ("Local stack"): compose gains `redis:7-alpine` on both services, a `postern-session` transit key, a confirm policy that carries the write and session keys and nothing on the read key, and an `api` that verifies confirm's session tokens at `http://confirm:8080/session/jwks.json` with the same URI audience on both sides. `tests/test_vault_live.py` bootstraps the same objects and proves the confirm token signs with `postern-session`, cannot sign with `postern-read`, and that `/session/jwks.json` publishes `session-1.v<N>`.

**Files:**
- Modify: `docker-compose.yml` (header comment, `redis`, `vault-init`, `api`, `confirm`)
- Modify: `tests/test_vault_live.py` (`SESSION_KEY`, `WRITE_POLICY`, the `vault` fixture, `TestTheConfirmServiceSignsSessionsAndNothingOnTheReadKey`)

- [ ] **Step 1: Write the failing tests**

In `tests/test_vault_live.py`, replace:

```python
from services.api.settings import Settings
from services.confirm.minter import build_write_minter
from services.confirm.settings import ConfirmSettings
```

with:

```python
from services.api.settings import Settings
from services.confirm.main import create_confirm_app
from services.confirm.minter import build_write_minter
from services.confirm.session_token import build_session_minter
from services.confirm.settings import ConfirmSettings
```

In `tests/test_vault_live.py`, replace:

```python
WRITE_KEY = "postern-write"
ROOT = "postern-live-root"  # noqa: S105 -- the dev-mode container's own token
```

with:

```python
WRITE_KEY = "postern-write"
SESSION_KEY = "postern-session"
ROOT = "postern-live-root"  # noqa: S105 -- the dev-mode container's own token
```

In `tests/test_vault_live.py`, replace:

```python

WRITE_POLICY = """
path "transit/sign/postern-write" { capabilities = ["update"] }
path "transit/keys/postern-write" { capabilities = ["read"] }
path "transit/sign/postern-read"  { capabilities = ["update"] }
path "transit/keys/postern-read"  { capabilities = ["read"] }
"""
```

with:

```python

#: The confirm service's policy: the write key and the session key, and since
#: the layer-1 session token nothing on the read key.
WRITE_POLICY = """
path "transit/sign/postern-write"   { capabilities = ["update"] }
path "transit/keys/postern-write"   { capabilities = ["read"] }
path "transit/sign/postern-session" { capabilities = ["update"] }
path "transit/keys/postern-session" { capabilities = ["read"] }
"""
```

In `tests/test_vault_live.py`, replace:

```python
    THE FIVE STEPS ARE THE OPERATOR CHECKLIST, EXECUTED. Enable transit, create
    two RSA keys, write two policies, mint one token per policy. Nothing here
    is a test fixture's convenience: this is `docker-compose.yml`'s
```

with:

```python
    THE FIVE STEPS ARE THE OPERATOR CHECKLIST, EXECUTED. Enable transit, create
    three RSA keys (read, write, session), write two policies, mint one token
    per policy. Nothing here
    is a test fixture's convenience: this is `docker-compose.yml`'s
```

In `tests/test_vault_live.py`, replace:

```python
            _raise_for(root.post("/v1/sys/mounts/transit", json={"type": "transit"}))
            for name in (READ_KEY, WRITE_KEY):
                _raise_for(root.post(f"/v1/transit/keys/{name}", json={"type": "rsa-2048"}))
```

with:

```python
            _raise_for(root.post("/v1/sys/mounts/transit", json={"type": "transit"}))
            for name in (READ_KEY, WRITE_KEY, SESSION_KEY):
                _raise_for(root.post(f"/v1/transit/keys/{name}", json={"type": "rsa-2048"}))
```

In `tests/test_vault_live.py`, replace:

```python
        assert _moduli(read_source.public_jwks()).isdisjoint(_moduli(write_source.public_jwks()))

```

with:

```python
        assert _moduli(read_source.public_jwks()).isdisjoint(_moduli(write_source.public_jwks()))


class TestTheConfirmServiceSignsSessionsAndNothingOnTheReadKey:
    """The confirm token after the layer-1 session token: SESSION yes, READ no."""

    def test_the_session_minter_signs_through_the_session_transit_key(
        self, vault: LiveVault
    ) -> None:
        settings = ConfirmSettings(
            vault=_credentialled(vault, vault.write_token),
            vault_session_key_name=SESSION_KEY,
        )
        minter, source = build_session_minter(settings)
        claims = minter.prepare(customer=CUST, client_id="c", scope="accounts:read", sid="s")
        token = minter.sign(claims)
        decoded = jwt.decode(
            token, KeySet.import_key_set(source.public_jwks()), algorithms=["RS256"]
        )
        assert decoded.claims["jti"] == claims.jti
        assert decoded.header["kid"].startswith("session-1.v")
        source.close()

    def test_the_confirm_token_cannot_sign_with_the_read_key(self, vault: LiveVault) -> None:
        impostor = VaultTransitKeySource(
            address=vault.address, key_name=READ_KEY, kid="read-1", token=vault.write_token
        )
        with pytest.raises(VaultTransitError, match="403"):
            impostor.sign({"sub": CUST.value, "aud": "accounts.svc"})
        impostor.close()

    def test_the_api_token_cannot_sign_with_the_session_key(self, vault: LiveVault) -> None:
        impostor = VaultTransitKeySource(
            address=vault.address, key_name=SESSION_KEY, kid="session-1", token=vault.read_token
        )
        with pytest.raises(VaultTransitError, match="403"):
            impostor.sign({"sub": CUST.value, "aud": "https://mcp.postern.test/mcp"})
        impostor.close()

    async def test_session_jwks_publishes_the_versioned_session_kids(
        self, vault: LiveVault
    ) -> None:
        from postern_core.auth.device_keys import no_enrolled_devices

        settings = ConfirmSettings(
            app_assertion_jwks_uri="https://issuer.test/.well-known/jwks.json",
            app_assertion_issuer="https://issuer.test",
            app_assertion_audience="postern-confirm",
            vault=_credentialled(vault, vault.write_token),
            vault_write_key_name=WRITE_KEY,
            vault_session_key_name=SESSION_KEY,
            allow_non_uri_audience=True,
            allow_process_local_sessions=True,
        )
        app = create_confirm_app(settings, device_key_store=no_enrolled_devices())
        async with httpx2.AsyncClient(
            transport=httpx2.ASGITransport(app=app), base_url="http://confirm.test"
        ) as client:
            session = (await client.get("/session/jwks.json")).json()
            write = (await client.get("/.well-known/jwks.json")).json()
        kids = [entry["kid"] for entry in session["keys"]]
        assert kids and all(kid.startswith("session-1.v") for kid in kids)
        assert _moduli(session).isdisjoint(_moduli(write))
        app.state.postern_session_key_source.close()
        app.state.postern_write_key_source.close()

```

- [ ] **Step 2: Run them**

Run: `uv run pytest tests/test_vault_live.py -q`

Expected: 23 passed. These pass on their first run, and that is expected: the live-Vault tests bootstrap their own container with the same key and policy the compose file creates, and the session minter they drive landed in Task 2. What they prove is the policy an operator applies; `docker-compose.yml` is configuration no test reads, checked with `docker compose -f docker-compose.yml config -q`, which must print nothing and exit 0.

- [ ] **Step 3: Implement**

In `docker-compose.yml`, replace:

```yaml
#
# `POSTERN_JWKS_URI`/`POSTERN_TOKEN_ISSUER` point at `backend-stub`'s own
# disposable local IdP (`stub/backend.py`'s `/.well-known/jwks.json` and
# `/mint-token` routes), not left empty as the plan originally drafted this
# file. Two Task 13 findings, both against the current `services/api/*`
# code, drove that:
#
```

with:

```yaml
#
# `POSTERN_JWKS_URI`/`POSTERN_TOKEN_ISSUER` on `api` point at `confirm`'s
# `/session/jwks.json` and its session issuer since the layer-1 session token:
# the whole device grant, refresh and recall run end to end in this stack, and
# the customer token `api` accepts is the one `POST /token` issues. Until then
# they pointed at `backend-stub`'s disposable local IdP (`stub/backend.py`'s
# `/.well-known/jwks.json` and `/mint-token` routes), which still exists but
# whose tokens name another issuer and another key, so `api` refuses them.
# They were never left empty, which the plan originally drafted, for two
# Task 13 findings, both against the `services/api/*` code of the day:
#
```

In `docker-compose.yml`, replace:

```yaml
      test: ["CMD-SHELL", "pg_isready -U postern"]
      interval: 2s
```

with:

```yaml
      test: ["CMD-SHELL", "pg_isready -U postern"]
      interval: 2s
      timeout: 3s
      retries: 15

  # The shared state both services need: the ZT-7 list, device codes, refresh
  # families and the risk session store. `services/confirm` refuses to start
  # without POSTERN_REDIS_URL unless POSTERN_ALLOW_PROCESS_LOCAL_SESSIONS is
  # set, and this stack does not set it, so a recall at `/scan` reaches `api`.
  # The same image `tests/conftest.py`'s `redis_url` fixture runs.
  redis:
    image: redis:7-alpine
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 2s
```

In `docker-compose.yml`, replace:

```yaml
  # and demonstrable against this stack with one curl. `postern-write` carries
  # both, which is the device-grant exception `services/confirm/settings.py`
  # records: that service mints the browser's read token in the same atomic step
  # as the write one.
  #
```

with:

```yaml
  # and demonstrable against this stack with one curl. `postern-write` carries
  # the write key and the SESSION key, which signs the layer-1 access tokens
  # `confirm` issues at `POST /token`, and nothing on the read key: no process
  # holds READ and WRITE together since the layer-1 session token.
  #
```

In `docker-compose.yml`, replace:

```yaml
      vault write -f transit/keys/postern-write type=rsa-2048;
      echo "path \"transit/sign/postern-read\" { capabilities = [\"update\"] }
```

with:

```yaml
      vault write -f transit/keys/postern-write type=rsa-2048;
      vault write -f transit/keys/postern-session type=rsa-2048;
      echo "path \"transit/sign/postern-read\" { capabilities = [\"update\"] }
```

In `docker-compose.yml`, replace:

```yaml
      path \"transit/keys/postern-write\" { capabilities = [\"read\"] }
      path \"transit/sign/postern-read\" { capabilities = [\"update\"] }
      path \"transit/keys/postern-read\" { capabilities = [\"read\"] }" | vault policy write postern-write -;
      vault token create -policy=postern-read -period=24h -field=token > /vault-tokens/read.token;
```

with:

```yaml
      path \"transit/keys/postern-write\" { capabilities = [\"read\"] }
      path \"transit/sign/postern-session\" { capabilities = [\"update\"] }
      path \"transit/keys/postern-session\" { capabilities = [\"read\"] }" | vault policy write postern-write -;
      vault token create -policy=postern-read -period=24h -field=token > /vault-tokens/read.token;
```

In `docker-compose.yml`, replace:

```yaml
      chmod 0444 /vault-tokens/read.token /vault-tokens/write.token;
      echo "vault-init: transit enabled, two keys, two policies, two tokens";
      '
```

with:

```yaml
      chmod 0444 /vault-tokens/read.token /vault-tokens/write.token;
      echo "vault-init: transit enabled, three keys, two policies, two tokens";
      '
```

In `docker-compose.yml`, replace:

```yaml
      POSTERN_DATABASE_URL: postgresql+asyncpg://postern_app:postern_app@db:5432/postern
      POSTERN_JWKS_URI: http://backend-stub:8081/.well-known/jwks.json
      POSTERN_TOKEN_ISSUER: "https://postern-local-dev.invalid"
      POSTERN_AUDIENCE: "postern"
      POSTERN_STRICT_HEADERS: "0"
```

with:

```yaml
      POSTERN_DATABASE_URL: postgresql+asyncpg://postern_app:postern_app@db:5432/postern
      # THE SESSION TOKENS `confirm` ISSUES, verified against its
      # `/session/jwks.json`. The issuer is confirm's default
      # POSTERN_SESSION_TOKEN_ISSUER and the audience is the same resource URI
      # confirm stamps as `aud`, so neither container needs
      # POSTERN_ALLOW_NON_URI_AUDIENCE. The fetch is lazy, at the first token.
      POSTERN_JWKS_URI: http://confirm:8080/session/jwks.json
      POSTERN_TOKEN_ISSUER: "https://auth.postern.internal"
      POSTERN_AUDIENCE: "https://mcp.postern.internal/mcp"
      POSTERN_REDIS_URL: redis://redis:6379/0
      POSTERN_STRICT_HEADERS: "0"
```

In `docker-compose.yml`, replace:

```yaml
      db:
        condition: service_healthy
      db-grants:
        condition: service_completed_successfully
      vault-init:
        condition: service_completed_successfully

  # Plan 3 Task 6: the write path, brought up alongside `api` to verify the
```

with:

```yaml
      db:
        condition: service_healthy
      db-grants:
        condition: service_completed_successfully
      redis:
        condition: service_healthy
      vault-init:
        condition: service_completed_successfully

  # Plan 3 Task 6: the write path, brought up alongside `api` to verify the
```

In `docker-compose.yml`, replace:

```yaml
    environment:
      # BOTH KEYS THROUGH ONE VAULT TOKEN, and that is the device-grant
      # exception rather than a hole: this service mints the browser's read
      # token in the same atomic step as the write one, so its policy carries
      # `update` on both sign paths. What no policy anywhere grants is the
      # reverse -- `api`'s token has nothing on `transit/sign/postern-write`.
      POSTERN_VAULT_ADDR: http://vault:8200
```

with:

```yaml
    environment:
      # THE WRITE KEY AND THE SESSION KEY THROUGH ONE VAULT TOKEN, and no
      # read key: `POST /token` issues a layer-1 session signed by
      # `postern-session`, which `api` verifies at `/session/jwks.json`. What
      # no policy anywhere grants is the reverse -- `api`'s token has nothing
      # on `transit/sign/postern-write` or `transit/sign/postern-session`.
      POSTERN_VAULT_ADDR: http://vault:8200
```

In `docker-compose.yml`, replace:

```yaml
      POSTERN_VAULT_WRITE_KEY_NAME: postern-write
      POSTERN_VAULT_READ_KEY_NAME: postern-read
      POSTERN_APP_ASSERTION_JWKS_URI: http://backend-stub:8081/.well-known/jwks.json
```

with:

```yaml
      POSTERN_VAULT_WRITE_KEY_NAME: postern-write
      POSTERN_VAULT_SESSION_KEY_NAME: postern-session
      # The MCP server's resource URI, stamped as `aud` on every access token
      # and equal to `api`'s POSTERN_AUDIENCE above.
      POSTERN_SESSION_TOKEN_AUDIENCE: "https://mcp.postern.internal/mcp"
      # Refresh families and recalls must reach `api`: the same Redis.
      POSTERN_REDIS_URL: redis://redis:6379/0
      POSTERN_APP_ASSERTION_JWKS_URI: http://backend-stub:8081/.well-known/jwks.json
```

In `docker-compose.yml`, replace:

```yaml
        condition: service_completed_successfully
      vault-init:
```

with:

```yaml
        condition: service_completed_successfully
      redis:
        condition: service_healthy
      vault-init:
```

- [ ] **Step 4: Format, then run the gate**

Run: `uv run ruff format packages services tests && make ci`

Expected: exit 0 (3738 passed at validation).

- [ ] **Step 5: Commit**

```bash
git add docker-compose.yml tests/test_vault_live.py
git commit -m "chore(compose): redis, the session transit key, and api pointed at confirm" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 12: End to end across both services, and the audit counts

The spec's Testing section, end to end: the QR pairing test extended with `tools/list` on a `services/api` configured per section 8, a refresh, and `tools/list` with the new token; a recalled session refused at the api before the backend is touched, counted as `tests/test_zt7_revocation_reachable.py` counts; a session-key token for another audience refused; each of section 9's count predicates against one pairing, one exchange and one refresh; and `minted()` reached only for the two grants. No production code changes: every behaviour here landed in Tasks 6 to 10.

**Files:**
- Modify: `tests/test_qr_pairing_end_to_end.py`
- Create: `tests/test_session_end_to_end.py`

- [ ] **Step 1: Write the failing tests**

In `tests/test_qr_pairing_end_to_end.py`, replace:

```python

``POST /token`` ends the flow with a layer-1 session: an access token whose
audience is the MCP server, signed by the SESSION key, and a refresh token. A
replay of the spent code is refused. The regression this file was written for
still runs: before 30 September 2026 ``/token`` returned a layer-2 backend
```

with:

```python

``POST /token`` ends the pairing with a layer-1 session: an access token
whose audience is the MCP server, signed by the SESSION key, and a refresh
token. A replay of the spent code is refused. ``services/api``, configured as
spec section 8 says, then lists its tools for that access token, the browser
refreshes, and the api lists them again for the new one. The regression this file was written for
still runs: before 30 September 2026 ``/token`` returned a layer-2 backend
```

In `tests/test_qr_pairing_end_to_end.py`, replace:

```python
The audit trail is read back at the end: one row each for the scan and the
approval, the mint, and the replay, joined on the device code's handle.
"""
```

with:

```python
The audit trail is read back at the end: one row each for the scan and the
approval, the mint, the replay and the refresh, the first four joined on the
device code's handle.
"""
```

In `tests/test_qr_pairing_end_to_end.py`, replace:

```python
from services.api.main import create_app as create_api_app
from services.api.settings import Settings as ApiSettings
```

with:

```python
from services.api.main import create_app as create_api_app
from services.api.session_verifier import SessionTokenVerifier
from services.api.settings import Settings as ApiSettings
```

In `tests/test_qr_pairing_end_to_end.py`, replace:

```python
    PAIRING_TOOL_NAME,
    SCAN_TOOL_NAME,
```

with:

```python
    PAIRING_TOOL_NAME,
    REFRESH_TOOL_NAME,
    SCAN_TOOL_NAME,
```

In `tests/test_qr_pairing_end_to_end.py`, replace:

```python
SAME_ORIGIN = {"Sec-Fetch-Site": "same-origin"}

```

with:

```python
SAME_ORIGIN = {"Sec-Fetch-Site": "same-origin"}
#: The MCP server's resource URI, on both services, as spec section 8 asks.
RESOURCE = "https://mcp.postern.test/mcp"
_META = {
    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
    "io.modelcontextprotocol/clientCapabilities": {},
}

```

In `tests/test_qr_pairing_end_to_end.py`, replace:

```python
    built = create_confirm_app(
        replace(ConfirmSettings.for_testing(), database_url=pg_url),
        assertion_verifier=verifier,
```

with:

```python
    built = create_confirm_app(
        replace(
            ConfirmSettings.for_testing(),
            database_url=pg_url,
            session_token_audience=RESOURCE,
            allow_non_uri_audience=False,
        ),
        assertion_verifier=verifier,
```

In `tests/test_qr_pairing_end_to_end.py`, replace:

```python
    return built, key_pair

```

with:

```python
    return built, key_pair


async def _tools_listed(api: Any, access_token: str) -> set[str]:
    """``tools/list`` on ``services/api`` with a bearer; the names it returns."""
    async with httpx2.AsyncClient(
        transport=httpx2.ASGITransport(app=api), base_url="http://api.test"
    ) as client:
        response = await client.post(
            "/mcp",
            headers={
                "Authorization": f"Bearer {access_token}",
                "Accept": "application/json, text/event-stream",
                "Mcp-Method": "tools/list",
                "Mcp-Name": "",
                "MCP-Protocol-Version": "2026-07-28",
            },
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {"_meta": _META}},
        )
    assert response.status_code == 200, response.text
    return {tool["name"] for tool in response.json()["result"]["tools"]}

```

In `tests/test_qr_pairing_end_to_end.py`, replace:

```python
async def test_a_browser_and_a_phone_complete_a_pairing_through_every_route(
    app: tuple[Starlette, RSAKeyPair], clean: Database, api: tuple[Any, dict[str, Any]]
) -> None:
```

with:

```python
async def test_a_browser_and_a_phone_complete_a_pairing_through_every_route(
    app: tuple[Starlette, RSAKeyPair],
    clean: Database,
    api: tuple[Any, dict[str, Any]],
    pg_url: str,
) -> None:
```

In `tests/test_qr_pairing_end_to_end.py`, replace:

```python

    # THE CONTROL THAT MAKES THE REGRESSION MEAN SOMETHING. A token the api's
```

with:

```python

        # THE API, CONFIGURED PER SPEC SECTION 8: its customer JWKS is this
        # confirm's /session/jwks.json (fetched in process), its issuer the
        # session issuer, its audience the same resource URI.
        settings = confirm.state.settings
        jwks_uri = "https://auth.test/session/jwks.json"
        verified_api = create_api_app(
            replace(
                ApiSettings.for_testing(),
                database_url=pg_url,
                customer_jwks_uri=jwks_uri,
                customer_token_issuer=settings.session_token_issuer,
                audience=RESOURCE,
            ),
            auth_override=SessionTokenVerifier(
                jwks_uri=jwks_uri,
                issuer=settings.session_token_issuer,
                audience=RESOURCE,
                required_scopes=None,
                cache_ttl_seconds=300.0,
                http_client=httpx2.AsyncClient(transport=transport),
            ),
        )
        async with verified_api.router.lifespan_context(verified_api):
            first_listing = await _tools_listed(verified_api, token.json()["access_token"])
            refreshed = await browser.post(
                "/token",
                data={
                    "grant_type": "refresh_token",
                    "refresh_token": token.json()["refresh_token"],
                },
            )
            second_listing = await _tools_listed(verified_api, refreshed.json()["access_token"])

    # THE CONTROL THAT MAKES THE REGRESSION MEAN SOMETHING. A token the api's
```

In `tests/test_qr_pairing_end_to_end.py`, replace:

```python
    assert_no_body_carries_a_token_the_api_trusts(
        [token.text, replay.text],
        api_jwks,
```

with:

```python
    assert_no_body_carries_a_token_the_api_trusts(
        [token.text, replay.text, refreshed.text],
        api_jwks,
```

In `tests/test_qr_pairing_end_to_end.py`, replace:

```python
    assert stored.session_id == claims["sid"]

    async with clean.sessionmaker() as s:
        written = list((await s.execute(select(AuditEntry).order_by(AuditEntry.id))).scalars())
    everything = [(r.tool_name, r.outcome, r.detail) for r in written]
```

with:

```python
    assert stored.session_id == claims["sid"]
    # Accepted, not 401: the customer has granted no consent in this test, so
    # the catalog is the one tool that needs none.
    assert first_listing == second_listing == {"start_session"}
    renewed = session_claims(refreshed, confirm)
    assert renewed["sid"] == claims["sid"]
    assert renewed["jti"] != claims["jti"]

    async with clean.sessionmaker() as s:
        rows = list((await s.execute(select(AuditEntry).order_by(AuditEntry.id))).scalars())
    written = [r for r in rows if r.tool_name.startswith("device_grant.")]
    everything = [(r.tool_name, r.outcome, r.detail) for r in written]
```

In `tests/test_qr_pairing_end_to_end.py`, replace:

```python
        (TOKEN_TOOL_NAME, OUTCOME_RAISED, DETAIL_DEVICE_CODE_SPENT),
    ]
    successes = [r for r in written if r.outcome == OUTCOME_RETURNED]
    assert [(r.tool_name, r.detail) for r in successes] == [
```

with:

```python
        (TOKEN_TOOL_NAME, OUTCOME_RAISED, DETAIL_DEVICE_CODE_SPENT),
        (REFRESH_TOOL_NAME, OUTCOME_RETURNED, None),
    ]
    successes = [
        r for r in written if r.outcome == OUTCOME_RETURNED and r.tool_name != REFRESH_TOOL_NAME
    ]
    assert [(r.tool_name, r.detail) for r in successes] == [
```

In `tests/test_qr_pairing_end_to_end.py`, replace:

```python
    chain = [
        r for r in written if r.tool_name != PAIRING_TOOL_NAME or r.outcome == OUTCOME_RETURNED
    ]
```

with:

```python
    chain = [
        r
        for r in written
        if r.tool_name in {SCAN_TOOL_NAME, TOKEN_TOOL_NAME}
        or (r.tool_name == PAIRING_TOOL_NAME and r.outcome == OUTCOME_RETURNED)
    ]
```

In `tests/test_qr_pairing_end_to_end.py`, replace:

```python
    assert successes[2].arguments["session_id"] == claims["sid"]
```

with:

```python
    assert successes[2].arguments["session_id"] == claims["sid"]
    assert written[-1].arguments["session_id"] == claims["sid"]
```

Create `tests/test_session_end_to_end.py` with:

```python
"""The layer-1 session across both services, and the audit counts it leaves.

``services/confirm`` issues a session; ``services/api``, configured as spec
section 8 says -- its customer JWKS is confirm's ``/session/jwks.json``, its
issuer confirm's session issuer, its audience the same resource URI -- accepts
it on ``tools/list`` and ``tools/call``, and after a refresh accepts the new
one. Both services share one Redis, so a recall at confirm's ``POST /scan``
is refused on the api's next call, counted in backend touches the way
``tests/test_zt7_revocation_reachable.py`` counts them.

The api's verifier fetches confirm's key set over an in-process transport
pointed at the confirm app, so no socket is opened; everything else is the
two composition roots.

The last two tests pin spec section 9's reading of the table: each count
predicate is asked of a table holding one pairing, one exchange and one
refresh, and ``minted()`` is only ever reached for ``device_grant.token`` and
``device_grant.refresh``.
"""

from __future__ import annotations

import ast
import dataclasses
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any
from uuid import uuid4

import httpx2
import pytest
from fastmcp.server.auth.providers.jwt import JWTVerifier, RSAKeyPair
from postern_core.auth.device_keys import no_enrolled_devices
from postern_core.identity import CustomerRef
from postern_core.store.engine import Database
from sqlalchemy import text
from starlette.applications import Starlette

from services.api.session_verifier import SessionTokenVerifier
from services.confirm.audit import REFRESH_TOOL_NAME, TOKEN_TOOL_NAME, PairingAudit
from services.confirm.main import create_confirm_app
from services.confirm.settings import ConfirmSettings
from tests.device_grant_helpers import qr_for, scan_in_store, session_claims, stored_code
from tests.fixtures.append_only_bypass import (
    delete_audit_rows_by_bypassing_the_append_only_triggers,
)
from tests.test_device_grant import AUDIENCE as APP_AUDIENCE
from tests.test_device_grant import ISSUER as APP_ISSUER
from tests.test_device_grant import bearer
from tests.test_zt7_revocation_reachable import (
    RecordingBackend,
    _app,
    _call,
    _consent,
    _list_tools,
    _refused,
    _serving,
    _settings,
    _succeeded,
)

RESOURCE = "https://mcp.postern.test/mcp"
CUSTOMER = "cust_e2e0b"
VICTIM = "cust_e2e0a"
REPO = Path(__file__).resolve().parent.parent


@pytest.fixture(scope="module")
def key_pair() -> RSAKeyPair:
    return RSAKeyPair.generate()


@pytest.fixture()
async def clean(database: Database) -> AsyncIterator[Database]:
    async with database.sessionmaker() as s:
        await delete_audit_rows_by_bypassing_the_append_only_triggers(s)
        await s.commit()
    yield database


@pytest.fixture()
def shared_redis(monkeypatch: pytest.MonkeyPatch, redis_url: str) -> str:
    """One Redis key space for both services, as a deployment shares one."""
    monkeypatch.setenv("POSTERN_REDIS_URL", redis_url)
    monkeypatch.setenv("POSTERN_REDIS_KEY_PREFIX", f"e2e{uuid4().hex[:12]}:")
    return redis_url


@pytest.fixture()
def confirm(pg_url: str, key_pair: RSAKeyPair, shared_redis: str) -> Starlette:
    settings = dataclasses.replace(
        ConfirmSettings.for_testing(),
        database_url=pg_url,
        session_token_audience=RESOURCE,
        allow_non_uri_audience=False,
        allow_process_local_sessions=False,
    )
    return create_confirm_app(
        settings,
        assertion_verifier=JWTVerifier(
            public_key=key_pair.public_key, issuer=APP_ISSUER, audience=APP_AUDIENCE
        ),
        device_key_store=no_enrolled_devices(),
    )


def _api(confirm: Starlette, pg_url: str, backend: RecordingBackend) -> Any:
    """``services/api`` configured per spec section 8, verifying against confirm."""
    session_issuer = confirm.state.settings.session_token_issuer
    jwks_uri = "https://confirm.test/session/jwks.json"
    verifier = SessionTokenVerifier(
        jwks_uri=jwks_uri,
        issuer=session_issuer,
        audience=RESOURCE,
        required_scopes=None,
        cache_ttl_seconds=300.0,
        http_client=httpx2.AsyncClient(transport=httpx2.ASGITransport(app=confirm)),
    )
    settings = dataclasses.replace(
        _settings(pg_url),
        customer_jwks_uri=jwks_uri,
        customer_token_issuer=session_issuer,
        audience=RESOURCE,
    )
    return _app(settings, backend, auth_override=verifier)


def _tool_names(payload: dict[str, Any]) -> set[str]:
    """The tools a successful ``tools/list`` names; it carries no ``isError``."""
    assert "error" not in payload, payload
    return {tool["name"] for tool in payload["result"]["tools"]}


async def _confirm_post(app: Starlette, path: str, **kwargs: Any) -> httpx2.Response:
    async with httpx2.AsyncClient(
        transport=httpx2.ASGITransport(app=app), base_url="https://confirm.test"
    ) as client:
        return await client.post(path, **kwargs)


async def _pair_and_exchange(
    confirm: Starlette, key_pair: RSAKeyPair, approver: str
) -> tuple[Any, dict[str, Any]]:
    """A pairing approved by ``approver`` and exchanged; the code and the session."""
    started = await _confirm_post(
        confirm, "/device_authorization", json={"client_id": "claude-code"}
    )
    device = started.json()
    code = await stored_code(confirm, device["user_code"])
    await scan_in_store(confirm, device["user_code"], approver)
    approved = await _confirm_post(
        confirm,
        "/approve",
        json={"user_code": device["user_code"]},
        headers=bearer(key_pair, approver),
    )
    assert approved.status_code == 200, approved.text
    exchanged = await _confirm_post(
        confirm, "/token", data={"grant_type": "device_code", "device_code": device["device_code"]}
    )
    assert session_claims(exchanged, confirm)["sub"] == approver
    return code, exchanged.json()


async def test_the_api_accepts_the_session_and_the_refreshed_one(
    confirm: Starlette, pg_url: str, database: Database, key_pair: RSAKeyPair, clean: Database
) -> None:
    backend = RecordingBackend()
    api = _api(confirm, pg_url, backend)
    _, session = await _pair_and_exchange(confirm, key_pair, CUSTOMER)

    async with _consent(database, CustomerRef(value=CUSTOMER)):
        async with _serving(api) as client:
            assert "accounts.list" in _tool_names(
                await _list_tools(client, token=session["access_token"])
            )
            _succeeded(await _call(client, "accounts.list", token=session["access_token"]))

            refreshed = await _confirm_post(
                confirm,
                "/token",
                data={"grant_type": "refresh_token", "refresh_token": session["refresh_token"]},
            )
            renewed = refreshed.json()
            assert session_claims(refreshed, confirm)["sub"] == CUSTOMER
            assert "accounts.list" in _tool_names(
                await _list_tools(client, token=renewed["access_token"])
            )
            _succeeded(await _call(client, "accounts.list", token=renewed["access_token"]))

    assert backend.paths == ["/accounts", "/accounts"]


async def test_a_token_for_another_audience_is_refused_by_the_api(
    confirm: Starlette, pg_url: str, key_pair: RSAKeyPair, clean: Database
) -> None:
    """A layer-2-shaped token signed with the SESSION key but for a domain
    service's audience: right key, wrong audience, refused."""
    backend = RecordingBackend()
    api = _api(confirm, pg_url, backend)
    minter = confirm.state.session_minter
    claims = minter.prepare(
        customer=CustomerRef(value=CUSTOMER), client_id="c", scope="accounts:read", sid="x"
    )
    foreign = dataclasses.replace(claims, aud="accounts.svc")
    async with _serving(api) as client:
        response = await client.post(
            "/mcp",
            headers={"Authorization": f"Bearer {minter.sign(foreign)}"},
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
        )
    assert response.status_code == 401
    assert backend.paths == []


async def test_a_recalled_session_is_refused_at_the_api_before_the_backend(
    confirm: Starlette, pg_url: str, database: Database, key_pair: RSAKeyPair, clean: Database
) -> None:
    """Spec section 7: B approved A's pairing, A's client holds B's session,
    A's scan recalls it, and A's client's next call reaches no backend."""
    backend = RecordingBackend()
    api = _api(confirm, pg_url, backend)
    code, session = await _pair_and_exchange(confirm, key_pair, CUSTOMER)

    async with _consent(database, CustomerRef(value=CUSTOMER)):
        async with _serving(api) as client:
            _succeeded(await _call(client, "accounts.list", token=session["access_token"]))
            assert backend.paths == ["/accounts"]

            conflict = await _confirm_post(
                confirm,
                "/scan",
                json={"user_code": code.user_code_display, "qr": qr_for(code)},
                headers=bearer(key_pair, VICTIM),
            )
            assert conflict.json()["error"] == "scan_conflict"

            _refused(await _call(client, "accounts.list", token=session["access_token"]))
            _refused(await _list_tools(client, token=session["access_token"]))

    assert backend.paths == ["/accounts"], "the recalled session reached the backend"


PREDICATES = {
    "pairings granted": (
        "tool_name = 'device_grant.approve' AND outcome = 'returned' AND detail IS NULL",
        1,
    ),
    "repeat approvals": (
        "tool_name = 'device_grant.approve' AND outcome = 'returned' "
        "AND detail = 'already_approved'",
        0,
    ),
    "pairings scanned": (
        "tool_name = 'device_grant.scan' AND outcome = 'returned' AND detail IS NULL",
        1,
    ),
    "repeat scans": (
        "tool_name = 'device_grant.scan' AND outcome = 'returned' "
        "AND detail IN ('already_scanned','already_approved')",
        0,
    ),
    "sessions issued": (
        "tool_name = 'device_grant.token' AND outcome = 'returned' AND detail IS NULL",
        1,
    ),
    "refreshes issued": (
        "tool_name = 'device_grant.refresh' AND outcome = 'returned' AND detail IS NULL",
        1,
    ),
    "recalls completed": ("tool_name = 'device_grant.recall' AND outcome = 'returned'", 0),
}


async def test_each_count_predicate_counts_one_endpoint(
    confirm: Starlette, key_pair: RSAKeyPair, clean: Database
) -> None:
    """One pairing (scanned over HTTP), one exchange, one refresh: every
    predicate of spec section 9 counts exactly its own event, and the naive
    ``LIKE 'device_grant.%'`` one counts four."""
    started = await _confirm_post(
        confirm, "/device_authorization", json={"client_id": "claude-code"}
    )
    code = await stored_code(confirm, started.json()["user_code"])
    scanned = await _confirm_post(
        confirm,
        "/scan",
        json={"user_code": code.user_code_display, "qr": qr_for(code)},
        headers=bearer(key_pair, CUSTOMER),
    )
    assert scanned.status_code == 200, scanned.text
    approved = await _confirm_post(
        confirm,
        "/approve",
        json={"user_code": code.user_code_display},
        headers=bearer(key_pair, CUSTOMER),
    )
    assert approved.status_code == 200
    exchanged = await _confirm_post(
        confirm, "/token", data={"grant_type": "device_code", "device_code": code.device_code}
    )
    refreshed = await _confirm_post(
        confirm,
        "/token",
        data={"grant_type": "refresh_token", "refresh_token": exchanged.json()["refresh_token"]},
    )
    assert refreshed.status_code == 200

    async with clean.sessionmaker() as s:
        for name, (predicate, expected) in PREDICATES.items():
            # The predicates are this file's own constants, not input.
            query = "SELECT count(*) FROM audit_log WHERE " + predicate  # noqa: S608
            found = (await s.execute(text(query))).scalar()
            assert found == expected, name
        naive = (
            await s.execute(
                text(
                    "SELECT count(*) FROM audit_log WHERE tool_name LIKE 'device_grant.%' "
                    "AND outcome = 'returned' AND detail IS NULL"
                )
            )
        ).scalar()
    assert naive == 4


def test_minted_is_reached_only_for_the_two_grants() -> None:
    """Every function in the device grant that calls ``minted()`` builds its
    ``PairingAudit`` with ``TOKEN_TOOL_NAME`` or ``REFRESH_TOOL_NAME``."""
    tree = ast.parse((REPO / "services/confirm/device_auth.py").read_text())
    allowed = {"TOKEN_TOOL_NAME", "REFRESH_TOOL_NAME"}
    callers = 0
    for function in (n for n in ast.walk(tree) if isinstance(n, ast.AsyncFunctionDef)):
        calls = [n for n in ast.walk(function) if isinstance(n, ast.Call)]
        mints = [c for c in calls if isinstance(c.func, ast.Attribute) and c.func.attr == "minted"]
        if not mints:
            continue
        callers += 1
        built = [
            kw.value.id
            for c in calls
            if isinstance(c.func, ast.Name) and c.func.id == PairingAudit.__name__
            for kw in c.keywords
            if kw.arg == "tool_name" and isinstance(kw.value, ast.Name)
        ]
        assert built and set(built) <= allowed, (function.name, built)
    assert callers == 2
    assert {TOKEN_TOOL_NAME, REFRESH_TOOL_NAME} == {"device_grant.token", "device_grant.refresh"}
```

- [ ] **Step 2: Run them**

Run: `uv run pytest tests/test_qr_pairing_end_to_end.py tests/test_session_end_to_end.py -q`

Expected: 6 passed. These tests pass on their first run: they measure behaviour Tasks 6 to 10 built, and a failure here is a defect in one of those tasks, not a missing implementation.

- [ ] **Step 3: Format, then run the gate**

Run: `uv run ruff format packages services tests && make ci`

Expected: exit 0 (3743 passed at validation).

- [ ] **Step 4: Commit**

```bash
git add tests/test_qr_pairing_end_to_end.py tests/test_session_end_to_end.py
git commit -m "test: the layer-1 session end to end across both services" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 13: Documentation, decision 0010's amendment and the mobile contract

Spec section 11 and the "Docs that go stale" list: decision 0010's amendment (the 10-minute and 1-hour windows and the controls that replace the 60-second one, plus the unbuilt pruning of revoked jtis), notes on 0012 and on `dev-docs/qr-page-spec.md`, the confirm-service guide, glossary, getting-started variables and audit guide (with section 9's predicate table), the mobile pairing contract (the token, the scopes note, the recalled `scan_conflict`, the 503 retry-once rule), and CLAUDE.md's confirm paragraph, operator item 6 and red-team scenario 2. Four code comments Task 6 left stale ("read token") are corrected. Nothing here is checked by a test beyond `make ci`'s citation and format gates.

**Files:**
- Modify: `CLAUDE.md`
- Modify: `dev-docs/decisions/0010-dpop-sender-constraint.md`
- Modify: `dev-docs/decisions/0012-device-code-single-use.md`
- Modify: `dev-docs/qr-page-spec.md`
- Modify: `docs/integration/mobile-app-pairing-contract.md`
- Modify: `docs/user-guide/components/audit.md`
- Modify: `docs/user-guide/components/confirm-service.md`
- Modify: `docs/user-guide/getting-started.md`
- Modify: `docs/user-guide/glossary.md`
- Modify: `packages/postern-core/src/postern_core/auth/device_codes.py`
- Modify: `packages/postern-core/src/postern_core/store/audit.py`
- Modify: `services/confirm/audit.py`
- Modify: `services/confirm/auth.py`

- [ ] **Step 1: Implement**

In `CLAUDE.md`, replace:

```markdown

**`services/confirm` is the write path, not a JWKS publisher.** On top of the write key whose public half it serves at `/.well-known/jwks.json`, it holds the RFC 8628 device grant (`POST /device_authorization`, `POST /token`, `POST /scan`, `POST /approve`, and the browser's pairing page at `GET /verify` with `/verify/qr.svg`, `/verify/state`, `/verify.js` and `/verify.css`) and the challenge approval callback (`POST /challenges/{challenge_id}/approve`), which is where a backend write endpoint is actually reached. The Architecture table below puts the device grant on `services/api`; the code puts it here, and this service holds a READ key for the grant — a deliberate exception to the key split, recorded in `ConfirmSettings`' docstring, and the only key it publishes is still the write one. `POST /token` mints nothing with it since 30 September 2026: an approved code gets 503 `temporarily_unavailable` until a layer-1 session token exists, because the read token it used to return was a layer-2 token the accounts backend accepts. `AppAssertionMiddleware` authenticates every path by omission: only `/.well-known/jwks.json`, `/device_authorization`, `/token` and the five `/verify` routes are in `PUBLIC_PATHS` (decision record 0021 is why the page is served here), so `/scan`, `/approve` and the challenge callback all require a verified banking-app assertion; `/approve` takes the pairing's `user_code` and nothing else that names it, and approves only for the customer whose app scanned it first at `/scan`, by compare-and-set in the device-code store; an approval requires, additionally, an Ed25519 signature from a device the operator enrolled, checked over bytes built from the stored challenge row; a ZT-7 revocation check refuses a revoked customer on all four paths that know one; up to two correlated `audit_log` rows are written per approval, on the read path's own schema; and a body-size limit, a rate limiter and a device-code store cap sit in front of all of it.

```

with:

```markdown

**`services/confirm` is the write path, not a JWKS publisher.** On top of the write key whose public half it serves at `/.well-known/jwks.json`, it holds the RFC 8628 device grant (`POST /device_authorization`, `POST /token`, `POST /scan`, `POST /approve`, and the browser's pairing page at `GET /verify` with `/verify/qr.svg`, `/verify/state`, `/verify.js` and `/verify.css`) and the challenge approval callback (`POST /challenges/{challenge_id}/approve`), which is where a backend write endpoint is actually reached. The Architecture table below puts the device grant on `services/api`; the code puts it here. `POST /token` issues a layer-1 session: an access token whose audience is the MCP server, signed by a third key (SESSION) that signs nothing else and is published at `/session/jwks.json`, plus a rotating refresh token in a one-hour family (`dev-docs/device-grant-session-token-spec.md`). This service holds no READ key since then, so no process holds READ and WRITE together; `services/api` verifies the session token against confirm's `/session/jwks.json`. `AppAssertionMiddleware` authenticates every path by omission: only `/.well-known/jwks.json`, `/session/jwks.json`, `/device_authorization`, `/token` and the five `/verify` routes are in `PUBLIC_PATHS` (decision record 0021 is why the page is served here), so `/scan`, `/approve` and the challenge callback all require a verified banking-app assertion; `/approve` takes the pairing's `user_code` and nothing else that names it, and approves only for the customer whose app scanned it first at `/scan`, by compare-and-set in the device-code store; an approval requires, additionally, an Ed25519 signature from a device the operator enrolled, checked over bytes built from the stored challenge row; a ZT-7 revocation check refuses a revoked customer on all four paths that know one; up to two correlated `audit_log` rows are written per approval, on the read path's own schema; and a body-size limit, a rate limiter and a device-code store cap sit in front of all of it.

```

In `CLAUDE.md`, replace:

```markdown

**What this repository now does.** `KeySource` is a signing CAPABILITY, not a key: `sign(claims) -> str`, never `signing_key() -> RSAKey`. Set `POSTERN_VAULT_ADDR` and `choose_key_source` builds a `VaultTransitKeySource`, which signs through `POST /v1/<mount>/sign/<key>`. The private key is generated inside Vault and there is no request that returns it: measured against Vault 1.20.4, `GET /v1/transit/export/signing-key/<name>` answers **HTTP 400, "private key material is not exportable"**, to the **root** token. Not 403 from a policy you could widen. `docker compose up` brings a dev-mode Vault with two keys, two policies and two scoped tokens, and `tests/test_vault_live.py` runs 19 tests against a real Vault inside `make ci`.

```

with:

```markdown

**What this repository now does.** `KeySource` is a signing CAPABILITY, not a key: `sign(claims) -> str`, never `signing_key() -> RSAKey`. Set `POSTERN_VAULT_ADDR` and `choose_key_source` builds a `VaultTransitKeySource`, which signs through `POST /v1/<mount>/sign/<key>`. The private key is generated inside Vault and there is no request that returns it: measured against Vault 1.20.4, `GET /v1/transit/export/signing-key/<name>` answers **HTTP 400, "private key material is not exportable"**, to the **root** token. Not 403 from a policy you could widen. `docker compose up` brings a dev-mode Vault with three keys, two policies and two scoped tokens, and `tests/test_vault_live.py` runs 23 tests against a real Vault inside `make ci`.

```

In `CLAUDE.md`, replace:

```markdown
- **A real Vault.** Dev mode is in-memory storage, auto-unseal and a known root token. You owe storage, unseal and operations.
- **Two transit keys**, `rsa-2048` or `rsa-4096`, created WITHOUT `exportable=true`. An exportable key answers that export 200 and this whole control is off.
- **Two policies, and they are the read/write split.** No wildcards, no `transit/*`, nothing on `transit/export/*`. The write policy carries the read key too, and that is the device-grant exception `ConfirmSettings` records: the grant minted the browser's read token until 30 September 2026 and the key stays wired while `POST /token` issuance is disabled. Nothing grants the reverse.
- **An auth method, not a static token.** Kubernetes, AWS IAM or AppRole, one role per service. A Vault Agent renders the token to a file and `POSTERN_VAULT_TOKEN_PATH` names it; the file is re-read on every call, so a renewal is picked up without a restart. `POSTERN_VAULT_TOKEN` is the local-work escape hatch and does not belong in a deployment.
```

with:

```markdown
- **A real Vault.** Dev mode is in-memory storage, auto-unseal and a known root token. You owe storage, unseal and operations.
- **Three transit keys** (read, write, session), `rsa-2048` or `rsa-4096`, created WITHOUT `exportable=true`. An exportable key answers that export 200 and this whole control is off.
- **Two policies, and they are the read/write split.** No wildcards, no `transit/*`, nothing on `transit/export/*`. The api's policy carries the read key only; confirm's carries the write key and the session key, and nothing on the read key since the layer-1 session token. Do not raise a session key's `min_available_version` past a version whose 10-minute access tokens may still be in flight.
- **An auth method, not a static token.** Kubernetes, AWS IAM or AppRole, one role per service. A Vault Agent renders the token to a file and `POSTERN_VAULT_TOKEN_PATH` names it; the file is re-read on every call, so a renewal is picked up without a restart. `POSTERN_VAULT_TOKEN` is the local-work escape hatch and does not belong in a deployment.
```

In `CLAUDE.md`, replace:

```markdown
1. Injected instruction in a transaction memo attempting to initiate a payment (A1)
2. QR relay to a separate browser; confirm pairing-code mismatch blocks it (A2)
3. Token captured from one client, replayed from different infrastructure (A4, ZT-6)
```

with:

```markdown
1. Injected instruction in a transaction memo attempting to initiate a payment (A1)
2. QR relay to a separate browser; confirm pairing-code mismatch blocks it (A2). And the form it does not block: a victim scanning and approving a pairing the attacker started (the `verification_uri_complete` sent as a lure). Only one customer scans, so no recall fires; measure how long the resulting session family lasts (up to 1 hour, refreshable without the victim)
3. Token captured from one client, replayed from different infrastructure (A4, ZT-6)
```

In `dev-docs/decisions/0010-dpop-sender-constraint.md`, replace:

```markdown
> 5.5 states it.

```

with:

```markdown
> 5.5 states it.

> **Amended with the layer-1 session token (`dev-docs/device-grant-session-token-spec.md`).**
> The table below counts a 60-second lifetime, and that describes the layer-2
> delegation token only. The token a client holds is now a layer-1 access
> token that lives **10 minutes** inside a refresh family that lives **1
> hour**, so the bearer-theft window is 10 minutes for a stolen access token
> and up to 1 hour for a stolen refresh token nobody has noticed. What
> replaces the short lifetime as a compensating control for those two:
>
> - **The per-call `jti` check.** `services/api/middleware/revocation.py`'s
>   `RevocationMiddleware` asks the ZT-7 store about the access token's `jti`
>   on every `tools/call` and `tools/list`, so a token is cut on its next call
>   once anything lists it. Recall at `POST /scan` and reuse detection both
>   list every live `jti` of the family they revoke.
> - **Refresh-token rotation with reuse detection** (RFC 9700 §4.14.2). A
>   rotated token presented again revokes the whole family. It detects, it
>   does not prevent: until both parties have presented, the thief refreshes
>   freely.
> - **The revocation checks at every refresh**: the customer, the
>   customer-client pair, the kill switch, every live access `jti`, and a
>   family created at or before a customer revocation is refused and revoked
>   for good.
>
> Not built, and needed before a revoked-`jti` set can be pruned: neither
> revocation store records when a revoked `jti` expires, so the set only grows.
> A companion sorted set scored by `exp` beside the `SADD` would let a sweep
> remove expired members.

```

In `dev-docs/decisions/0012-device-code-single-use.md`, replace:

```markdown
**Date:** 2026-09-26

```

with:

```markdown
**Date:** 2026-09-26

> **Since the layer-1 session token** the exchange issues a session (an access
> token for the MCP server and a refresh token), not the read token this record
> argues about, and spends the code in the same compare-and-set that records the
> family's `session_id`. The single-use argument below is unchanged: one
> approved code is worth one grant. Between 30 September 2026 and the session
> token the exchange issued nothing and spent nothing.

```

In `dev-docs/qr-page-spec.md`, replace:

```markdown
**Reviewed by:** a security review and a code-fit review, both on 29 September 2026, and a spec review on 30 September 2026, all folded in below.

```

with:

```markdown
**Reviewed by:** a security review and a code-fit review, both on 29 September 2026, and a spec review on 30 September 2026, all folded in below.
**Superseded in part** by `dev-docs/device-grant-session-token-spec.md`: `/token` now issues a layer-1 session rather than a read token, and a session swap noticed after the exchange (`conflict_exchanged`) now recalls the session the exchange issued. The "Session swap" residual below, §5's `conflict_exchanged` line and §6's "`/token` is unchanged" describe the tree before that change.

```

In `docs/integration/mobile-app-pairing-contract.md`, replace:

```markdown
5. The app calls `POST /approve` with the `user_code` (section 6).
6. The AI client's own poll of `POST /token` then receives no token: since 30 September 2026 it answers 503 `temporarily_unavailable` ("session token issuance is not enabled") until a layer-1 session token exists, because the read token it used to return was one the accounts backend accepts. The app plays no part in that step.

```

with:

```markdown
5. The app calls `POST /approve` with the `user_code` (section 6).
6. The AI client's own poll of `POST /token` then receives a layer-1 session: an access token that only this deployment's MCP server accepts (10 minutes, `aud` = the MCP server), and a refresh token whose family lasts one hour from the exchange. The app plays no part in that step. The session can be ended from the server side: a recall (section 5's `scan_conflict`), ZT-7 revocation of the customer, or reuse of a rotated refresh token.

```

In `docs/integration/mobile-app-pairing-contract.md`, replace:

```markdown

**The scopes shown are not the scopes enforced.** Read from `services/confirm/device_auth.py`: `POST /token` issues no token after approval since 30 September 2026, and the one it issued before that was always `aud=accounts.svc`, `scope=accounts:read`, 60-second expiry, whatever the pairing's `scopes` string said. The string is what the client asked for, stored and echoed back, and no code path in this repository reads it after `/scan`. The app can show it faithfully; it cannot promise the user that it describes any token.

```

with:

```markdown

**The scopes shown are recorded on the token, not enforced by it.** `POST /token` copies the pairing's `scopes` string, canonicalized (split on spaces, de-duplicated, sorted), into the access token's `scope` claim and the refresh family. Nothing validates the values against a vocabulary, and `services/api` enforces no scope from the token: what a client can read is decided by the customer's consents in the database. The app can show the scopes faithfully as what the client asked for; it cannot promise the user they limit anything.

```

In `docs/integration/mobile-app-pairing-contract.md`, replace:

```markdown
| 400 | `qr_stale` | A genuine token for this pairing, older than the window. | "The code on your screen has changed. Scan it again." The QR is still on the page if nobody has scanned it yet. |
| 400 | `scan_conflict` | Another customer's app scanned this pairing first. The server has now cancelled the pairing, including one already approved, because `/token` issues nothing and so spends no code. A code spent by an earlier build is the one case where nothing is cancelled. | "This pairing was cancelled because another device scanned the same code. Start again from your AI client, and do not share your screen while pairing." Both cases give the same body. |
| 401 | `invalid_token` | No valid assertion (section 3). | Refresh the assertion once and retry; if it fails again, a generic failure. |
```

with:

```markdown
| 400 | `qr_stale` | A genuine token for this pairing, older than the window. | "The code on your screen has changed. Scan it again." The QR is still on the page if nobody has scanned it yet. |
| 400 | `scan_conflict` | Another customer's app scanned this pairing first. If the AI client had not yet exchanged the pairing, the server has cancelled it. If it had, the server has **recalled the session** that exchange issued: the refresh family is revoked and its access tokens are refused by the MCP server on their next call. | "This pairing was cancelled because another device scanned the same code. Start again from your AI client, and do not share your screen while pairing." Both cases give the same body. |
| 503 | `temporarily_unavailable` | Only after a `scan_conflict` on an exchanged pairing, when the recall could not complete. Carries `Retry-After: 1`. | **Retry once, immediately, with the same body.** The `qr` token is valid for 10 to 12 seconds, so a later retry answers `qr_stale` and recalls nothing. If the retry fails too, tell the user the pairing may still be active and to contact the bank. |
| 401 | `invalid_token` | No valid assertion (section 3). | Refresh the assertion once and retry; if it fails again, a generic failure. |
```

In `docs/integration/mobile-app-pairing-contract.md`, replace:

```markdown

The app can then tell the user to return to their computer, but the AI client gets nothing from its next poll yet: `POST /token` answers 503 `temporarily_unavailable` with a `Retry-After` header for an approved code and issues nothing, and does not spend the code. Issuance returns with the pending session-token change.

```

with:

```markdown

The app can then tell the user to return to their computer: the AI client's next poll of `POST /token` is issued the session and spends the code.

```

In `docs/integration/mobile-app-pairing-contract.md`, replace:

```markdown
- **400: never retry automatically.** Every 400 on these paths is a final answer about this request or this pairing. `qr_stale` is recovered by a new scan by the user, not by resending the same token.
- **429 and 503: honour `Retry-After`** (seconds). `Retry-After` is the seconds left in a fixed 60-second window, so it can be anything from 1 to 60, and a `/scan` retry after a 429 will usually answer `qr_stale` because the 10-to-12-second `qr` window has passed; tell the user to scan again instead of retrying silently.
- **401:** fetch a fresh assertion and retry once.
```

with:

```markdown
- **400: never retry automatically.** Every 400 on these paths is a final answer about this request or this pairing. `qr_stale` is recovered by a new scan by the user, not by resending the same token.
- **503 `temporarily_unavailable` on `/scan`: retry once, immediately, with the same body.** It means a recall did not complete (section 5), and only a retry inside the `qr` window can complete it.
- **429 and other 503s: honour `Retry-After`** (seconds). `Retry-After` is the seconds left in a fixed 60-second window, so it can be anything from 1 to 60, and a `/scan` retry after a 429 will usually answer `qr_stale` because the 10-to-12-second `qr` window has passed; tell the user to scan again instead of retrying silently.
- **401:** fetch a fresh assertion and retry once.
```

In `docs/user-guide/components/audit.md`, replace:

```markdown
| `POST /approve` | `device_grant.approve` | `/approve` |
| `POST /token` | `device_grant.token` | `/token` |

`WHERE tool_name LIKE 'device_grant.%'` returns the whole flow. An exception that
ends any of the three is recorded as `raised` under its class name.

```

with:

```markdown
| `POST /approve` | `device_grant.approve` | `/approve` |
| `POST /token` (`grant_type=device_code`) | `device_grant.token` | `/token` |
| `POST /token` (`grant_type=refresh_token`) | `device_grant.refresh` | `/token` |
| `POST /scan`, a recall | `device_grant.recall` | `/scan` |

`WHERE tool_name LIKE 'device_grant.%'` returns the whole flow. An exception that
ends any of them is recorded as `raised` under its class name. Rows from `/token`
and the recall carry the refresh family's `session_id` in `arguments`; no token, no
segment of one and no digest of one is ever written.

**Count by `tool_name`, never by outcome and detail alone.** Several endpoints write
`returned` with a NULL `detail` on success, so `WHERE tool_name LIKE
'device_grant.%' AND outcome = 'returned' AND detail IS NULL` adds pairings, scans,
sessions and refreshes together:

| Question | Predicate |
|---|---|
| Pairings granted | `tool_name = 'device_grant.approve' AND outcome = 'returned' AND detail IS NULL` |
| Repeat approvals | `tool_name = 'device_grant.approve' AND outcome = 'returned' AND detail = 'already_approved'` |
| Pairings scanned (first scans only) | `tool_name = 'device_grant.scan' AND outcome = 'returned' AND detail IS NULL` |
| Repeat scans | `tool_name = 'device_grant.scan' AND outcome = 'returned' AND detail IN ('already_scanned','already_approved')` |
| Sessions issued | `tool_name = 'device_grant.token' AND outcome = 'returned' AND detail IS NULL` |
| Refreshes issued | `tool_name = 'device_grant.refresh' AND outcome = 'returned' AND detail IS NULL` |
| Recalls completed | `tool_name = 'device_grant.recall' AND outcome = 'returned'` |

```

In `docs/user-guide/components/audit.md`, replace:

```markdown
  different customer.
- `POST /token` (the browser's poll): since 30 September 2026 nothing is issued. An
  approved code for a customer who is not revoked is answered 503 and recorded `raised`
  with `issuance_disabled`, at most one row per poll interval because a poll inside
  the interval is answered `slow_down` and writes nothing. The other recorded exits are
  `revoked`, `stored_identity_malformed` (the stored identity fails to parse), the
  exception's class name when the revocation store could not answer, and
  `device_code_spent` for a code an earlier build spent. An unknown or expired code,
  `slow_down` and `authorization_pending` write nothing, because none of them has read
  a customer off the code yet.
- `POST /device_authorization` (creating the code) writes nothing at all: it
```

with:

```markdown
  different customer.
- `POST /token`, `grant_type=device_code` (the browser's poll): `returned` with a
  NULL `detail` for the exchange that issued a session. The other recorded exits are
  `revoked` (now, or at or after the approval), `stored_identity_malformed` (the stored
  identity fails to parse), the exception's class name when the revocation store could
  not answer or the family store is full (`RefreshSessionStoreFull`), and
  `device_code_spent` for a replay or a lost concurrent claim. An unknown or expired
  code, an unserved `resource`, `slow_down` and `authorization_pending` write nothing,
  because none of them has read a customer off the code yet.
- `POST /token`, `grant_type=refresh_token`: written only once the caller presented a
  refresh token the family issued. `returned` with NULL for a rotation; `raised` with
  `refresh_reused`, `session_revoked`, `session_expired`,
  `session_generations_exhausted`, `client_id_mismatch`, `scope_exceeded`, `revoked`,
  `issued_before_revocation`, or a class name. A refresh token the family never issued
  writes nothing and logs one line per family per minute.
- A recall at `POST /scan` (a second customer's scan of a pairing already exchanged):
  `returned` when the family was revoked and every access `jti` listed in a shared
  store; `raised` with `recall_no_session`, `recall_local_only` or a class name
  otherwise. It names the recalled family's customer and shares the scan row's
  `call_id`; the scan row after it names the scanner.
- `POST /device_authorization` (creating the code) writes nothing at all: it
```

In `docs/user-guide/components/audit.md`, replace:

```markdown
30 September 2026: `/approve` takes a `user_code` and records `user_code_not_found`
for a miss, and the budget was removed with the old lookup. The `minted` method has no
caller until the session-token change.

```

with:

```markdown
30 September 2026: `/approve` takes a `user_code` and records `user_code_not_found`
for a miss, and the budget was removed with the old lookup. `issuance_disabled` (an
approved code answered 503 while issuance was disabled, on 30 September 2026) is
historical the same way.

```

In `docs/user-guide/components/confirm-service.md`, replace:

```markdown
3. **Write minter**, `build_write_minter()` wraps the write key for token minting
4. **Read key source**, reads `POSTERN_READ_KEY_PEM_PATH` (needed for device grant)
5. **Read minter**, `InternalTokenMinter` with read key (device grant exception)
6. **Device code store**, in-memory (dev) or Redis (production) via `create_device_code_store()`
7. **Database**, async SQLAlchemy engine for challenges table

```

with:

```markdown
3. **Write minter**, `build_write_minter()` wraps the write key for token minting
4. **Session key source and minter**, `build_session_minter()`: the SESSION key
   (`POSTERN_SESSION_KEY_PEM_PATH`, `POSTERN_VAULT_SESSION_KEY_NAME`, or generated
   with a warning), which signs the layer-1 access tokens `/token` issues and nothing else
5. **Device code store**, in-memory (dev) or Redis (production) via `create_device_code_store()`
6. **Refresh-family store**, in-memory or Redis via `create_refresh_session_store()`,
   capped at `POSTERN_MAX_REFRESH_SESSIONS`
7. **Database**, async SQLAlchemy engine for challenges table

The service **refuses to start without `POSTERN_REDIS_URL`** unless
`POSTERN_ALLOW_PROCESS_LOCAL_SESSIONS` is set: without shared state a refresh token
from one replica is refused at another, and a recall at `/scan` never reaches
`services/api`. It also refuses a `POSTERN_SESSION_TOKEN_ISSUER` that is not an
`https` URL or that equals another issuer it knows, and a
`POSTERN_SESSION_TOKEN_AUDIENCE` that is not an absolute `https` URI in normal form
(unless `POSTERN_ALLOW_NON_URI_AUDIENCE` is set) or that equals
`POSTERN_APP_ASSERTION_AUDIENCE`.

```

In `docs/user-guide/components/confirm-service.md`, replace:

```markdown

### Key split exception

The confirm service holds **both** read and write keys. This is a deliberate, documented
exception: the device grant used the read key to mint the browser's token, and the key
stays wired while that issuance is disabled (see "Token issuance is disabled" below). No
other code path hands one process both keys for general use, the separation is preserved
at startup.

```

with:

```markdown

### Keys

The confirm service holds the **write** key and the **session** key, and no read key.
Until the layer-1 session token it also held the read key, as a recorded exception,
because `/token` minted the browser a read token with it. No process holds READ and
WRITE together now: `services/api` holds READ, this service holds WRITE and SESSION.
The session key's public half is published at `/session/jwks.json`, and
`/.well-known/jwks.json` stays write-only; the two sets share no kid and no modulus.

```

In `docs/user-guide/components/confirm-service.md`, replace:

```markdown
| `POST` | `/device_authorization` | public | Generate device code + user_code (pairing code) |
| `POST` | `/token` | public | The browser's poll: an error until approved, then 503 (issuance disabled) |
| `GET` | `/verify` | public | The browser's pairing page: pairing code, QR, app link |
```

with:

```markdown
| `POST` | `/device_authorization` | public | Generate device code + user_code (pairing code) |
| `POST` | `/token` | public | `grant_type=device_code`: the browser's poll, an error until approved, then a layer-1 session. `grant_type=refresh_token`: rotate the refresh token for a fresh access token |
| `GET` | `/session/jwks.json` | public | The session key's public half, which `services/api` verifies access tokens against |
| `GET` | `/verify` | public | The browser's pairing page: pairing code, QR, app link |
```

In `docs/user-guide/components/confirm-service.md`, replace:

```markdown
`secrets.token_urlsafe(32)`) is the authority at `/token` and never appears in
the page, the QR or the page URL. All seven are listed in `PUBLIC_PATHS`, alongside `/.well-known/jwks.json` (eight entries in all), in
[`services/confirm/auth.py`](../../../services/confirm/auth.py); every other
```

with:

```markdown
`secrets.token_urlsafe(32)`) is the authority at `/token` and never appears in
the page, the QR or the page URL. All seven are listed in `PUBLIC_PATHS`, alongside `/.well-known/jwks.json` and `/session/jwks.json` (nine entries in all), in
[`services/confirm/auth.py`](../../../services/confirm/auth.py); every other
```

In `docs/user-guide/components/confirm-service.md`, replace:

````markdown
   ← 400 authorization_pending (until approved)
   ← 503 { "error": "temporarily_unavailable",
           "error_description": "session token issuance is not enabled" }
     (after approval)
```

### Token issuance is disabled

Since 30 September 2026 `/token` returns no token. For an approved, unexpired
code whose customer is not revoked it answers the 503 above with
`Retry-After` set to the poll interval (`POSTERN_DEVICE_POLL_INTERVAL_SECONDS`,
default 5), spends nothing, and writes one `audit_log` row with
`detail = 'issuance_disabled'`. The code stays unspent, so the next poll gets
the same answer; a poll that arrives inside the interval gets `400 slow_down`
and writes no row, as a pending code's does. A revoked customer still
gets `400 access_denied`, because the ZT-7 check runs first.

Until then it returned a read token: `aud=accounts.svc`, `scope=accounts:read`,
`act.sub=svc:postern`, 60 seconds, signed with the read key. That is a layer-2
backend token (handoff §7.1). Under Vault both services sign with transit key
`postern-read`, which `services/api` publishes at its JWKS and Istio trusts, so
any client that completed a pairing, a phishing client included, held a token
the accounts backend accepts. The browser should get a layer-1 session token
that only this deployment's MCP server accepts. That is a separate, later
change; until it lands, a completed pairing yields nothing the browser can use.

````

with:

````markdown
   ← 400 authorization_pending (until approved)
   ← 200 { "access_token": "<session token>", "token_type": "Bearer",
           "expires_in": 600, "refresh_token": "prt1.<sid>.<secret>",
           "scope": "<canonical scopes>" }
     (after approval; Cache-Control: no-store, Pragma: no-cache)

6. Browser → POST /token (grant_type=refresh_token, refresh_token=prt1...)
   ← 200, the same five keys with a new refresh token
```

### The layer-1 session

`dev-docs/device-grant-session-token-spec.md` is the contract. The access token's
`aud` is `POSTERN_SESSION_TOKEN_AUDIENCE` (the MCP server's resource URI, equal to
`services/api`'s `POSTERN_AUDIENCE`), its `iss` is `POSTERN_SESSION_TOKEN_ISSUER`,
it lives 600 seconds, carries `sub`, `client_id` (with `client_id_verified: false`),
`scope`, `sid` and `jti`, and carries no `act`, so no domain service accepts it. The
refresh token belongs to a **family** that lives one hour from the exchange; each
refresh rotates it, and presenting a rotated one revokes the whole family and lists
every live access `jti` on the ZT-7 store. The exchange spends the device code; a
replay is `invalid_grant`.

A `resource` parameter (RFC 8707), if sent, must name the audience after RFC 3986
normalization, or the answer is `400 invalid_target`. The two retryable answers, the
revocation store's outage and a full family store, are 503 with `Retry-After` set to
the poll interval, and an approved code's polls are paced at that interval.

**Recall.** When a second customer's `/scan` finds a pairing already exchanged
(`conflict_exchanged`), the session that exchange issued is recalled: the family is
revoked and its access tokens listed, so `services/api` refuses the next call. If
the recall fails, `/scan` answers **503 with `Retry-After: 1`**, and the app retries
once, immediately.

````

In `docs/user-guide/components/confirm-service.md`, replace:

```markdown
    customer_ref: str         # Verified assertion `sub`, empty until approved
    exchanged_at: datetime | None  # When /token spent it (nothing spends it since 2026-09-30)
    display_handle: str       # 128 random bits; keys the page, useless at /token
```

with:

```markdown
    customer_ref: str         # Verified assertion `sub`, empty until approved
    exchanged_at: datetime | None  # When /token spent it
    display_handle: str       # 128 random bits; keys the page, useless at /token
```

In `docs/user-guide/components/confirm-service.md`, replace:

````markdown
    scanner_ip: str | None    # Where the claiming /scan came from, set only by the claim
```
````

with:

````markdown
    scanner_ip: str | None    # Where the claiming /scan came from, set only by the claim
    session_id: str           # The refresh family /token created, set with exchanged_at
```
````

In `docs/user-guide/getting-started.md`, replace:

```markdown
| `POSTERN_TOKEN_ISSUER` | No | - | Expected issuer of customer JWTs. Leave unset for no-auth mode |
| `POSTERN_AUDIENCE` | No | `postern` | Expected `aud` claim on customer JWTs |
| `POSTERN_STRICT_HEADERS` | No | `0` | Enable strict MCP Streamable HTTP header validation (Mcp-Method/Mcp-Name must match body) |
```

with:

```markdown
| `POSTERN_TOKEN_ISSUER` | No | - | Expected issuer of customer JWTs. Leave unset for no-auth mode |
| `POSTERN_AUDIENCE` | No | `postern` | Expected `aud` claim on customer JWTs: the MCP server's resource URI, equal to the confirm service's `POSTERN_SESSION_TOKEN_AUDIENCE`. **Refused at startup** when `POSTERN_JWKS_URI` is set and this is not an absolute `https` URI in normal form, unless `POSTERN_ALLOW_NON_URI_AUDIENCE` is set; the default therefore works only without customer authentication |
| `POSTERN_ALLOW_NON_URI_AUDIENCE` | No | off | Local-stack flag: accept a non-URI `POSTERN_AUDIENCE`, with a warning. Read by both services |
| `POSTERN_STRICT_HEADERS` | No | `0` | Enable strict MCP Streamable HTTP header validation (Mcp-Method/Mcp-Name must match body) |
```

In `docs/user-guide/getting-started.md`, replace:

```markdown
| `POSTERN_DEVICE_APP_LINK_URI` | **Yes, in any deployment** | `https://app.postern.internal/pair` | Base of the universal link / app link the pairing QR encodes, as `?user_code=...&qr=...`. The default is a local placeholder: a deployment must set its own host and publish the Apple associated-domains and Android asset-links files for it, or a phone camera will not open the bank app. **Refused at startup** when it contains `?` or `#` (the QR appends `?user_code=...&qr=...`, which a fragment would swallow), unless it is an `https` URL with a hostname, and when its host equals `POSTERN_DEVICE_VERIFICATION_URI`'s host (case-insensitive, port ignored) |
| `POSTERN_DEVICE_CODE_TTL_SECONDS` | No | `900` (15 min) | Lifetime of a device code. Refused at startup below 30 seconds — the Redis store cannot represent a shorter one |
| `POSTERN_REDIS_DEVICE_CODE_TTL` | No | `900` (15 min) | Lifetime a device code gets when the caller passes no `expires_in`, on the Redis store. Refused below the same 30 seconds, and for the same reason: it sets the lifetime of the same object |
| `POSTERN_DEVICE_POLL_INTERVAL_SECONDS` | No | `5` | Minimum seconds between token polls. **At least 1**; must also stay below `POSTERN_DEVICE_CODE_TTL_SECONDS`, which is not checked: an interval at or above the lifetime expires the code before the browser may poll once |
| `POSTERN_READ_KEY_PEM_PATH` | No | - | Read key PEM path (needed for device grant token exchange) |
| `POSTERN_READ_KEY_KID` | No | `read-1` | Read key ID (must match API service) |
| `POSTERN_READ_TOKEN_ISSUER` | No | `https://mcp-read.internal` | Read token issuer (must match API service) |
| `POSTERN_BACKEND_BASE_URL` | No | `https://backend.internal` | Base URL for backend write endpoints (payments.svc, cards.svc) |
```

with:

```markdown
| `POSTERN_DEVICE_APP_LINK_URI` | **Yes, in any deployment** | `https://app.postern.internal/pair` | Base of the universal link / app link the pairing QR encodes, as `?user_code=...&qr=...`. The default is a local placeholder: a deployment must set its own host and publish the Apple associated-domains and Android asset-links files for it, or a phone camera will not open the bank app. **Refused at startup** when it contains `?` or `#` (the QR appends `?user_code=...&qr=...`, which a fragment would swallow), unless it is an `https` URL with a hostname, and when its host equals `POSTERN_DEVICE_VERIFICATION_URI`'s host (case-insensitive, port ignored) |
| `POSTERN_DEVICE_CODE_TTL_SECONDS` | No | `900` (15 min) | Lifetime of a device code. Refused at startup below 30 seconds, which the Redis store cannot represent, and above 900, the most the 4,800-second customer revocation stamp covers beside a one-hour session family |
| `POSTERN_REDIS_DEVICE_CODE_TTL` | No | `900` (15 min) | Lifetime a device code gets when the caller passes no `expires_in`, on the Redis store. Refused below the same 30 seconds, and for the same reason: it sets the lifetime of the same object |
| `POSTERN_DEVICE_POLL_INTERVAL_SECONDS` | No | `5` | Minimum seconds between token polls. **At least 1**; must also stay below `POSTERN_DEVICE_CODE_TTL_SECONDS`, which is not checked: an interval at or above the lifetime expires the code before the browser may poll once |
| `POSTERN_SESSION_KEY_PEM_PATH` | No | - | The SESSION key's PEM, which signs the layer-1 access tokens `/token` issues. Unset without Vault: an ephemeral key, with a warning. Refused together with `POSTERN_VAULT_ADDR` |
| `POSTERN_SESSION_KEY_KID` | No | `session-1` | Its kid, or under Vault the kid prefix (`session-1.v<N>`) |
| `POSTERN_VAULT_SESSION_KEY_NAME` | No | `postern-session` | The session transit key under Vault |
| `POSTERN_SESSION_TOKEN_ISSUER` | No | `https://auth.postern.internal` | `iss` of every access token, and what `services/api`'s `POSTERN_TOKEN_ISSUER` must equal. **Refused at startup** unless `https` with a host and no query or fragment, and when it equals `POSTERN_WRITE_TOKEN_ISSUER` or `POSTERN_APP_ASSERTION_ISSUER` |
| `POSTERN_SESSION_TOKEN_AUDIENCE` | **Yes, in any deployment** | `postern` | `aud` of every access token: the MCP server's resource URI, equal to `services/api`'s `POSTERN_AUDIENCE`. **Refused at startup** unless an absolute `https` URI in normal form (or `POSTERN_ALLOW_NON_URI_AUDIENCE` is set), and when it equals `POSTERN_APP_ASSERTION_AUDIENCE` |
| `POSTERN_ALLOW_PROCESS_LOCAL_SESSIONS` | No | off | Development flag: start without `POSTERN_REDIS_URL`, with refresh families and recalls in this process only. Without it the service **refuses to start** when `POSTERN_REDIS_URL` is unset |
| `POSTERN_MAX_REFRESH_SESSIONS` | No | `40000` | Ceiling on live refresh families: `POSTERN_MAX_DEVICE_CODES` times the lifetime ratio (3,600 s against 900 s). **At least 1** |
| `POSTERN_CONFIRM_RATE_LIMIT_SESSION_JWKS` | No | `300` | Per-address requests a minute to `/session/jwks.json`. **At least 1** |
| `POSTERN_BACKEND_BASE_URL` | No | `https://backend.internal` | Base URL for backend write endpoints (payments.svc, cards.svc) |
```

In `docs/user-guide/glossary.md`, replace:

```markdown
An opaque 40+ character code generated by the RFC 8628 device authorization flow. The
browser polls `/token` with it. Since 30 September 2026 an approved code gets a 503 and
no token: issuance is disabled until a layer-1 session token exists.

```

with:

```markdown
An opaque 40+ character code generated by the RFC 8628 device authorization flow. The
browser polls `/token` with it, and an approved code is exchanged once for a layer-1
session: an access token for the MCP server and a refresh token.

```

In `docs/user-guide/glossary.md`, replace:

```markdown
3. User scans with mobile app → confirms pairing code matches
4. Mobile app approves → browser polls `/token` → 503, no token (issuance disabled since 30 September 2026)

```

with:

```markdown
3. User scans with mobile app → confirms pairing code matches
4. Mobile app approves → browser polls `/token` → a layer-1 session (access token + refresh token)

```

In `packages/postern-core/src/postern_core/auth/device_codes.py`, replace:

```python
5. After approval, the browser polls ``/token`` with
   ``grant_type=device_code`` to receive a read token.

```

with:

```python
5. After approval, the browser polls ``/token`` with
   ``grant_type=device_code`` to receive a layer-1 session, and the code is
   spent with the session's family id (``consume_device_code``).

```

In `packages/postern-core/src/postern_core/store/audit.py`, replace:

```python
  endpoint, no approval reaches a backend write endpoint, no money moves, no
  read token is returned by `POST /token` (the mint is fail-closed on its
  row), and no device pairing survives -- `services/confirm/device_auth.py`'s
```

with:

```python
  endpoint, no approval reaches a backend write endpoint, no money moves, no
  session is returned by `POST /token` (the mint is fail-closed on its
  row), and no device pairing survives -- `services/confirm/device_auth.py`'s
```

In `services/confirm/audit.py`, replace:

```python
    would have been fail-closed in the response and fail-open in substance --
    the browser polls ``POST /token``, is handed a read token, and no row
    anywhere names who authorised it.
```

with:

```python
    would have been fail-closed in the response and fail-open in substance --
    the browser polls ``POST /token``, is handed a session, and no row
    anywhere names who authorised it.
```

In `services/confirm/audit.py`, replace:

```python
    signs a token, and once it has been returned nothing in this process can
    unmint it: there is no revocation list for a 60-second read token and
    ``services/api`` will accept it until it expires. So neither of the two
    obvious orders is right. Writing the row first refuses a customer who did
```

with:

```python
    signs a token, and once it has been returned nothing in this process can
    unmint it: ``services/api`` accepts a 10-minute access token until it
    expires or something lists its ``jti``, and nothing lists a token no row
    names. So neither of the two
    obvious orders is right. Writing the row first refuses a customer who did
```

In `services/confirm/auth.py`, replace:

```python
#:     was deleted from this endpoint's response (audit finding C-01), the
#:     most it can yield is the read token for the customer who approved that
#:     exact code on their own phone.
#: THE FIVE BELOW ARE THE PAIRING PAGE, added 2026-09-30, and all five are
```

with:

```python
#:     was deleted from this endpoint's response (audit finding C-01), the
#:     most it can yield is one layer-1 session for the customer who approved
#:     that exact code on their own phone. A refresh presents the refresh
#:     token it issued, which is the credential there.
#: THE FIVE BELOW ARE THE PAIRING PAGE, added 2026-09-30, and all five are
```

- [ ] **Step 2: Format, then run the gate**

Run: `uv run ruff format packages services tests && make ci`

Expected: exit 0 (3743 passed at validation).

- [ ] **Step 3: Commit**

```bash
git add CLAUDE.md dev-docs/decisions/0010-dpop-sender-constraint.md dev-docs/decisions/0012-device-code-single-use.md dev-docs/qr-page-spec.md docs/integration/mobile-app-pairing-contract.md docs/user-guide/components/audit.md docs/user-guide/components/confirm-service.md docs/user-guide/getting-started.md docs/user-guide/glossary.md packages/postern-core/src/postern_core/auth/device_codes.py packages/postern-core/src/postern_core/store/audit.py services/confirm/audit.py services/confirm/auth.py
git commit -m "docs: the layer-1 session token in the guides, the contract and decision 0010" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

## Spec coverage

Every section of `dev-docs/device-grant-session-token-spec.md` and every item of its Testing section, and the task that implements or tests it.

| Spec item | Task |
|---|---|
| §1 confirm is the layer-1 authorization server; api verifies and never signs | 2, 6, 10 |
| §1 read key removed from `create_confirm_app` and `ConfirmSettings`; inventory rows to `("api",)`; `device_auth_routes` loses `read_minter` (and takes no session parameters, discrepancy 17) | 9 (routes: 6) |
| §1 `test_the_confirm_settings_have_no_read_key_field` tightens | 9 |
| §2 session key via `choose_key_source`, `build_session_minter` in `session_token.py` after `build_write_minter` | 2 |
| §2 nine settings, inventory entries, `POSTERN_ALLOW_NON_URI_AUDIENCE` read by both | 1 (api read: 10) |
| §2 issuer and audience refusals, the flag's warning, `for_testing` sets both flags | 1 (wired: 5) |
| §2 `/session/jwks.json`, own route, write set stays write-only, disjoint kid and modulus | 2 |
| §2 kid and rotation under Vault; Vault key and policy | 2 (kid), 11 (Vault) |
| §3 `SessionTokenMinter.prepare`/`sign`, the claim table, no `act`/`nbf`, 600 s | 2 |
| §4 format, integrity, record, constants, interface, verdict, Redis layout, TTL rounding, atomicity, cap | 3 |
| §4 refuse to start without `POSTERN_REDIS_URL` unless the flag; ordering after `enforce_redis_requirement` | 5 |
| §4 compose `redis` service | 11 |
| §5 grant dispatch, pacing kept, `resource` rule and normalization, steps 0 to 5, response keys and headers | 6 |
| §5 `DETAIL_ISSUANCE_DISABLED` historical; `minted()` back in service; exit recount | 6 |
| §6 step 1 shape checks and `client_id` `-` at `/device_authorization` | 7 (`-`: 6) |
| §6 steps 2 to 10, unknown-hash log limiter, response | 7 |
| §6 step 6 store change: `customer_revoked_at`, ms, Redis `TIME`, Lua script, 4,800 s TTL, `from_env` ceiling | 4 (checks: 6, 7) |
| §7 recall steps 1 to 4, order, race, failure with `Retry-After: 1`, rows | 8 |
| §8 `SessionTokenVerifier`, TTL setting, floor, negative cache, lock, private-method pin, behavioural test | 10 |
| §8 audience URI refusal with and without the flag | 10 |
| §8 settings name no `session_key` | 9 |
| §8 local stack repointed | 11 |
| §9 `names(session_id=)`, key order | 6 |
| §9 new constants | 7, 8 |
| §9 rows by exit | 6, 7, 8 |
| §9 predicate table in the audit guide; the two pinning tests | 13, 12 |
| §10 ninth public path, rate-limit row, body limit tables | 2 |
| §11 0010 amendment; pruning need stated; mobile contract; red-team scenario 2 | 13 |
| Testing: session key branches, refusals, live Vault | 2, 1, 11 |
| Testing: JWKS | 2 |
| Testing: access token | 2 |
| Testing: store, both backends | 3 |
| Testing: startup | 5 |
| Testing: `device_code` exchange (keys, headers, verify, `resource` cases, store full, lost claim, failing discard, step 0, hotfix path gone) | 6 |
| Testing: refresh, every branch | 7 |
| Testing: revocation store | 4 (the 200 ms and 2 s edges: 7, 6) |
| Testing: `/device_authorization` `-` | 6 |
| Testing: recall, incl. the api refusal counted in backend touches | 8, 12 |
| Testing: api verifier | 10 |
| Testing: end to end over ASGI | 12 |
| Testing: audit | 6, 7, 8, 12 |
| Compatibility: the inverted hotfix assertions, pacing re-pointed, helper narrowed, control moved, hand-built settings | 6, 5 |
| Docs that go stale | 13 (compose comment: 11) |

## Spec discrepancies found while planning

Each is a point where the spec and the code, or two parts of the spec, disagree, or where the spec leaves a case open. The plan takes the conservative reading and says so.

1. **`rotate` must return more than a `Rotation`.** Section 4 types it `-> Rotation`, but `REUSED` and `REVOKED` "return the unexpired jtis" and section 6 step 8 re-runs step 4 "against what the transaction saw". **Plan:** `RotationOutcome(rotation, session, jtis)`.
2. **`create(session) -> None` cannot stamp `created_at` from Redis `TIME` and leave the caller's record right.** **Plan:** the store replaces `created_at`/`expires_at` from its own clock and returns the stored record; the handler never reads the argument's timestamps again.
3. **`DETAIL_SESSION_EXPIRED` at step 4 is almost unreachable.** Step 2 uses `get`, which section 4 defines as `None` for an expired family, so an expired family is `invalid_grant` with no row. **Plan:** both kept: the step-4 check (reached when a family expires between the lookup and the classification, and by `rotate`'s `GONE`), and a test pinning the no-row answer for the ordinary case.
4. **Step 6 checks the pair and the kill switch only "for each unexpired access jti".** A family whose access tokens have all expired would ask neither. **Plan:** `_refresh_revoked` also asks once without a `jti`.
5. **Section 5 says both retryable 503s carry `Retry-After`, "as the hotfix's did"**, but the revocation-outage 503 (`store_unavailable_response`) never had one. **Plan:** it gains an optional `retry_after`, passed at `/token`.
6. **`UNKNOWN` from `rotate` after the proof of possession has no branch.** **Plan:** it raises `RuntimeError`, recorded under its type name with a 500: it can only mean the record was replaced under an accepted presentation.
7. **Where the section 2 refusals run.** The spec lists them as startup refusals and its Compatibility section says a hand-built `ConfirmSettings(...)` "is refused at startup, twice over". **Plan:** `check_session_token_settings` runs in `create_confirm_app`, not `__post_init__`, so a settings object built without an app is unaffected.
8. **Key order of `arguments` cannot be asserted on a stored row** (Verified facts: `jsonb`). **Plan:** pinned on `PairingAudit._arguments()`; stored rows are compared as sets.
9. **The recall row's subject when the re-read row is gone.** Section 7 says B "from the re-read row". **Plan:** the re-read row's `customer_ref`, falling back to the pre-claim row's `scanned_by`, which is B by construction of `CONFLICT_EXCHANGED`.
10. **The section 9 count test "asserts a count of exactly one for each (and zero repeat approvals)"**, but one pairing, one exchange and one refresh produce no repeat scan and no recall. **Plan:** those two predicates assert zero, and the naive `LIKE` predicate asserts four.
11. **`POSTERN_REDIS_DEVICE_CODE_TTL` sets the same lifetime and gets no ceiling.** Section 6 binds only `POSTERN_DEVICE_CODE_TTL_SECONDS`, and confirm always passes `expires_in`, so the store default is not reached from confirm. **Plan:** unchanged, and listed under Concerns.
12. **`fakeredis` cannot run the section 6 Lua script**, and two existing ZT-7 fixtures used it. **Plan:** they move to the real Redis container (Verified facts).
13. **The spec anchors a citation to a test this change renames**, which would fail `make citations`. **Plan:** Task 6 rewrites that one sentence of the spec without the anchor.
14. **A failed JWKS fetch.** Section 8 floors refetches for unknown kids only; a JWKS endpoint that is down would still be asked once per request with a stale known kid. **Plan:** a failed fetch leaves the cache as it was and holds every further fetch to the same 30-second floor.
15. **The api's TTL read.** Section 8 says the api's `Settings` reads `POSTERN_VAULT_PUBLIC_KEY_TTL_SECONDS` "whether or not Vault is configured". **Plan:** through `public_key_ttl_from_env` in `postern_core.auth.vault`, which `vault_from_env` also calls, so the variable keeps one read site and one bound.
16. **Two concurrent exchanges in one process** answer one session and either `slow_down` or `invalid_grant` for the other, depending on scheduling. **Plan:** the renamed test accepts either.
17. **`device_auth_routes` does not take `session_minter` and `session_store`**, though section 1 says it does. Every handler reads the minter and both stores from `app.state`, where `create_confirm_app` puts them, so the two parameters would be accepted and never read. **Plan:** the function takes `store` and `settings`, as before, and loses `read_minter`; its docstring says why.

## Validation

Every task above was applied in order to a fresh clone of `origin/main` at `41a1701`, in a scratch directory outside the worktree, and committed there. (A first validation ran against the pairing-network-signal plan applied mechanically to `3c852d6`; the four review follow-ups merged since then applied under every task without a conflict, and the only code change on the rebase is discrepancy 17.) The code blocks in this plan were generated from those commits (`git show <commit>:<path>` for new files, exact unique replacements computed from the diff for modified ones), and the whole plan was then re-applied mechanically from this document to a second fresh clone and compared with the first: `git diff` between the two was empty after each of the thirteen tasks below, and `uv run ruff format packages services tests` changed nothing at any of them.

With this plan file tracked, `tools/check_citations.py` passes at `41a1701` and after each of the thirteen tasks.

`make ci` results in the scratch copy, Docker up, each on its own fresh clone of the task's commit:

| After task | `make ci` exit | Tests |
|---|---|---|
| 1 | 0 | 3552 passed, 0 failed |
| 2 | 0 | 3576 passed, 0 failed |
| 3 | 0 | 3628 passed, 0 failed |
| 4 | 0 | 3644 passed, 0 failed |
| 5 | 0 | 3654 passed, 0 failed |
| 6 | 0 | 3681 passed, 0 failed |
| 7 | 0 | 3710 passed, 0 failed |
| 8 | 0 | 3717 passed, 0 failed |
| 9 | 0 | 3718 passed, 0 failed |
| 10 | 0 | 3734 passed, 0 failed |
| 11 | 0 | 3738 passed, 0 failed |
| 12 | 0 | 3743 passed, 0 failed |
| 13 | 0 | 3743 passed, 0 failed |

The baseline, `41a1701` before Task 1, was exit 0 with 3487 passed. Every run is the full `make ci`: lint, fmt-check, type, imports, lock, citations, test.

## Concerns for the reviewer

- **The compose stack was not brought up.** `docker compose config -q` accepts the file and `tests/test_vault_live.py` bootstraps the same Vault objects, but no run of `docker compose up` exercised the repointed `api`, the `redis` service or a real pairing through the containers.
- **`SessionTokenVerifier` overrides a private method of a pinned dependency.** The signature pin and the counting-server test through `build_server` are the guard; both must be re-run on any `fastmcp` bump.
- **Redis script replication.** `revoke_customer_client` reads `TIME` inside `EVAL` and then writes; it runs on the suite's `redis:7-alpine`. Settled on 1 October 2026 from the Redis scripting introduction: effects replication is the default from Redis 5.0 and the only mode from 7.0, so the operator needs Redis 5.0 or later (7.0 or later recommended) with scripting enabled, and a non-clustered topology, as the spec's section 6 step 6 now says.
- **The recall's store step catches every `Exception`.** That is the spec's fail-closed 503, but a programming error in `_recall` would also surface as a 503 the app retries, not as a 500.
- **`POSTERN_REDIS_DEVICE_CODE_TTL` is not bounded by the new 900-second ceiling** (discrepancy 11).
- **The Redis refresh-session cap can be overshot, and one crash leaves an uncounted family** (added 1 October 2026, accepted, no Lua script). `create` reads the count and writes the family in separate round trips, so N concurrent creates can all land: the store holds at most `max_sessions + N`, the same overshoot `RedisDeviceCodeStore` already accepts. A crash between `SET NX` and `ZADD` leaves a family the index does not count, bounded only by its one-hour key TTL; that gap is this store's alone, since the device-code store writes key and index in one `MULTI`.
- **Tasks 6 and 13 edit design documents.** Task 6 rewrites one sentence of `dev-docs/device-grant-session-token-spec.md` so the citation gate stays green, and Task 13 edits `CLAUDE.md`, decisions 0010 and 0012 and `dev-docs/qr-page-spec.md`, as spec section 11 and its "Docs that go stale" list ask. The dated records under `docs/verification/` are left alone.
- **Task 6 is large** (twelve test files, one of them new and one the shared helper module, five production files and one sentence of the spec), because inverting the hotfix's assertions, adding `session_id` to every `consume_device_code` call and issuing the session cannot be split without a commit whose `make ci` fails. A reviewer may prefer to read its test changes by file.
- **Task 5's first `make ci` run failed two tests it does not touch**, `test_update_challenge_status_unexpired_refuses_a_row_past_its_deadline` and `test_update_challenge_status_expired_accepts_a_row_past_its_deadline` in `tests/test_store_challenges.py`, while a second `make ci` ran in parallel on the same Docker host. Both compare `expires_at` with PostgreSQL's `now()`. Task 5 changes no store code; `tests/test_store_challenges.py` then passed three times in a row at that commit, and a solo re-run of the full `make ci` exited 0 with 3654 passed, which is the number the table carries. It reads as a timing flake already on `main`, and this plan does not fix it.
- **This plan file, committed alone on `41a1701`, passes `make ci`** (3487 passed), run on a clone of the rebased worktree.
- **The end-to-end api tests fetch confirm's JWKS over an in-process ASGI transport.** The only socket-level JWKS fetch is `tests/test_session_verifier.py`'s counting server on `127.0.0.1`.
- **A signature that fails after the rotation forces a re-pair** (added 1 October 2026, after review of Task 7). Spec section 6 rotates at step 8 and signs at step 9, so a raise at step 9 leaves the family rotated and the client holding a retained token: its retry is reuse and revokes the family. The spec accepts this as fail-closed. Option for the spec owner: prepare, sign, then rotate and return the token only if the rotation succeeds; the invariant (no externally visible token whose jti is unrecorded) still holds; it changes spec section 6's stated order; not taken.

# Postern Persistence, Consent and Audit Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give Postern a Postgres-backed consent record that both filters and enforces which banking domains a customer has authorized, and an append-only audit entry for every tool call including the ones that fail.

**Architecture:** A new `postern_core.store` package owns the engine, session factory and two tables. Consent is enforced through FastMCP's per-tool `auth=` hook, which filters `tools/list` and rejects `tools/call` in one declaration, backed by a per-request cached lookup. Audit is a single `on_call_tool` middleware that wraps `call_next` in try/except, because failures reach it as raised exceptions and never as a result flag.

**Tech Stack:** Postgres 17, SQLAlchemy 2.0.52 async + asyncpg, Alembic 1.20, testcontainers 4.15, on the existing FastMCP 4.0.3 / Python 3.12 stack.

---

## Scope and boundaries

**In scope:** the `consents` and `audit_log` tables from handoff §9, consent-gated tool access, an audit row per tool call, Alembic migrations with a drift gate, and the composition wiring.

**Out of scope, deliberately:**

| Deferred | Why |
|---|---|
| `challenges` and `tokens` tables (handoff §9) | Both belong to the write path. Building them now means designing against a confirmation service whose API is open question §10.4. |
| Real consent granting | Consent is granted through the device-grant flow, Plan 4. This plan reads consent and seeds it in tests; nothing in it creates consent for a real customer. |
| Consent expiry enforcement and the 180-day RTS re-authentication | Needs the device-grant flow to re-authenticate. This plan stores `expires_at` and treats an expired row as absent. |
| Per-customer anomaly detection (ZT-5) | Needs a behavioural baseline this system has no data for. |
| Cross-customer contract tests (ZT-2) | Answered by the bank's domain services, not this repo. |

## Verified facts this plan depends on

Measured on 2026-09-14 against the installed packages and a real Postgres container. Anything not here is design reasoning.

**Consent enforcement, and this is the load-bearing finding:**

- `Middleware.on_list_tools` CAN filter: its return value is what `tools/list` returns (`fastmcp/server/middleware/middleware.py:260`, dispatched at `fastmcp/server/server.py:841-853`).
- **Filtering alone is NOT enforcement.** Measured: a token filtered out of `payments_create` called it by name and got `isError: false`. A hidden tool is still callable. The handoff's "should not appear in `tools/list`" wording describes a symptom, not the control.
- The correct mechanism is FastMCP's per-tool `auth=` parameter. `AuthCheck = Callable[[AuthContext], bool] | Callable[[AuthContext], Awaitable[bool]]` (`fastmcp/utilities/authorization.py:47`), and `_evaluate_check` awaits an awaitable result (`:230-250`), so an async DB lookup is legal. `FastMCP.list_tools` (`server.py:873-884`) and `_get_tool` (`server.py:886-914`) both honour it with no middleware at all: it filters the catalogue AND makes the call return `Unknown tool`, which discloses nothing.
- `require_scopes` cannot express this: `_RequireScopes.__call__` is a frozenset subset test against token scopes (`authorization.py:70-84`).
- A custom check makes `scope_requirements()` return `None` (`authorization.py:202-227`), so FastMCP emits a plain `AuthorizationError` rather than an RFC 6750 `insufficient_scope` step-up. Correct here: consent is not a scope the client can go obtain.

**Cost, not in any documentation:** `mcp/server/_streamable_http_modern.py:285-359` runs a full internal `tools/list` dispatch through the middleware chain before every `tools/call` carrying non-empty `arguments`, to validate `Mcp-Param-*` headers against the tool's `inputSchema`. So an uncached consent check runs twice per real call, and that path swallows exceptions (`except Exception: logger.exception(...); return None`), meaning a throwing consent lookup degrades header validation silently. Cache per request.

**Identity in hooks:** `get_access_token()` works inside a middleware hook over HTTP (`fastmcp/server/dependencies.py:606-636` reads `get_http_request().scope["user"]`), and returns `None` under the in-process `Client`. The repo's own `token_customer_resolver` works unchanged inside `on_list_tools`. An UNCAUGHT exception in a hook becomes JSON-RPC `-32603`, so the hook must catch `PermissionError` itself.

**Audit:**

- `on_call_tool` sees every call. **Failures arrive as raised exceptions, never as `ToolResult(is_error=True)`**: the `isError` envelope is built above the middleware chain. A hook reading `result.is_error` records zero failures.
- Four exception types cross the hook: `ToolError` (explicit), `ToolError` wrapping an arbitrary handler exception, `ValidationError` (argument coercion), `NotFoundError` (unknown tool). **`NotFoundError` also fires for a tool the caller is not authorized to see** (`server.py:900-913` returns `None` for both), so a denial and a typo are indistinguishable by exception type.
- `context.message` is `CallToolRequestParams` with `.name` and `.arguments`, available before `call_next` and still in scope after. `.arguments` is the RAW client dict before Pydantic coercion, which is what an audit log wants.
- `context.timestamp` is tz-aware UTC, stamped at chain entry (`middleware.py:107`).
- `context.message.meta` is `None` in the hook: the protocol envelope keys are stripped before it. Read `get_http_request().headers` if the protocol version is needed.
- **`ValidationError` carries the offending input value**, which is the masking leak path `CLAUDE.md` already documents. Scrub before persisting.

**Caching:** spec `schema.ts:1096-1109` defines `"private"` as "MAY be cached and reused only within the same authorization context. Caches MUST NOT be shared across authorization contexts". Spec prose adds that servers "**MUST NOT** rely on `cacheScope` alone to prevent unauthorized access". `tools.mdx:64-69` explicitly permits the set to "vary by the authorization presented on the request". FastMCP honours nothing itself: a hinted server is inert unless the client opts in (`fastmcp/server/caching.py:13-14`). There is **no** server-side `notifications/tools/list_changed` send path in FastMCP 4.0.3, and `stateless_http=True` holds no session to send one on, so TTL expiry is the only invalidation. Do NOT add `ResponseCachingMiddleware`: it partitions on `sha256(token.token)` (`fastmcp/server/middleware/caching.py:639-651`), so two tokens for one customer get separate entries and unauthenticated callers share one partition.

**Database:** none of `sqlalchemy`, `alembic`, `asyncpg`, `testcontainers`, `greenlet` are installed or in `uv.lock` today. `sqlalchemy[asyncio]` pulls `greenlet`; plain `sqlalchemy` does not.

**Alembic:** `uv run alembic init --template async migrations` from the repo root generates `migrations/` plus `alembic.ini`. The `pyproject_async` template generates a byte-identical `env.py`. **The generated `env.py` calls `fileConfig(config.config_file_name)` guarded only by `is not None`, but that attribute is the literal string `"alembic.ini"` even when the file is absent**, so a `pyproject.toml`-only configuration dies with `FileNotFoundError: alembic.ini doesn't exist`. `alembic check` exits 0 or 1 cleanly, which makes it a ready-made CI gate.

**Test fixtures:** the container fixture must be SYNC. The async `env.py` ends in `asyncio.run(...)`, so calling `command.upgrade` from inside a coroutine raises `RuntimeError: asyncio.run() cannot be called from a running event loop`. Pooled asyncpg connections break across event loops; the repo's existing `asyncio_default_test_loop_scope = "session"` prevents it, and `poolclass=NullPool` survives a mismatch outright. `testcontainers.postgres` is deprecated in favour of `testcontainers.community.postgres`, and `PostgresContainer` defaults to `driver="psycopg2"`, so `driver="asyncpg"` must be passed explicitly.

## Design decisions this plan locks in

**D1. Consent is enforced by per-tool `auth=`, never by catalogue filtering alone.** Filtering is a usability affordance; the `auth=` check is the control. Any tool added later that touches a consented domain must carry one.

**D2. Consent is read once per request and cached on the request.** Forced by the internal `tools/list` dispatch that doubles every lookup.

**D3. An expired consent row is treated as absent**, not as an error. Expiry enforcement and renewal belong to Plan 4.

**D4. The audit row is written even when the tool fails**, from an `except` branch that re-raises. An audit log that only records successes is worse than none, because it looks complete.

**D5. Audit arguments are scrubbed through the existing `FreeText` machinery before persisting.** The raw client dict can carry a PAN or IBAN, and an audit table is a long-lived store.

**D6 (revised in Task 2, see Step 8 below). `alembic check` is a standalone `make migrations` target, not a `make ci` gate.** The original plan made it a seventh `make ci` gate; that was overridden during execution because it would have required a running Postgres for `make ci` to pass, which conflicts with `make ci` running fully offline in under a second, the property that lets it run locally for free instead of billed Actions minutes. The same check runs instead as an explicit step in `.github/workflows/ci.yml` against a free Postgres service container, and must be run by hand before committing a model change. This was true through Task 2; **D7 below is where Task 3 changes it.**

**D7 (Task 3). Container-backed tests run in the default `make ci`, not behind a marker, degrading to an explicit skip when Docker is unreachable.** `tests/test_store_consents.py` needs a real Postgres, and unlike `alembic check` (D6), the `session` fixture's Postgres is a disposable container the tests own and tear down themselves, not a fixed URL an operator supplies. That difference is why D6's reasoning does not transfer: D6 keeps `alembic check` out of `make ci` because it needs a database *someone else* stands up; a `testcontainers` fixture needs nothing but a running Docker daemon and starts its own.

Measured on this machine, `postgres:17-alpine` already pulled, three consecutive runs: `make ci` was ~1.49s wall / 0.91s pytest before Task 3, ~3.3-3.8s wall / 2.4-2.6s pytest after, all as one `pytest` session because the container fixture is session-scoped (paid once per run, not per test). An addition of ~2s to a local pre-commit gate is not the kind of cost that justifies excluding the tests: Task 4 adds the actual consent-enforcement tests, the security control this whole plan exists to build, and a default `make ci` that skips them via a marker nobody remembers to pass would gate nothing that matters while still exiting 0.

Docker unreachable degrades to an explicit `pytest.skip("Docker is not reachable, skipping database-backed tests: ...")` raised from `pg_url` after a `docker.from_env().ping()` check, rather than the raw 15-frame `docker.errors.DockerException` traceback `PostgresContainer.__init__` produces on its own (measured, both ways, with `DOCKER_HOST` pointed at a socket that does not exist: the un-guarded fixture fails 7 times, once per dependent test, each with the full traceback; the guarded fixture skips 7 times in 0.01s total with one specific reason line each). `make test`'s pytest invocation also gained `-rs`, so every skip's reason prints in the summary `make ci` output, not just its count — a developer running `make ci` without Docker sees exactly why 7 tests didn't run, every time, rather than a "212 passed" that looks identical whether or not the consent tests executed. The CI workflow's `gates` job already has a Postgres service container (Task 2) and unconditionally runs `make test`, so there is one gate, dispatched manually, where these tests cannot be silently skipped.

## File structure

```
alembic.ini                                  # repo root, script_location -> migrations/
migrations/
  env.py                                     # async template, three edits
  versions/                                  # generated
packages/postern-core/src/postern_core/store/
  base.py                                    # DeclarativeBase
  engine.py                                  # create_async_engine + async_sessionmaker + lifespan close
  models.py                                  # ConsentRecord, AuditEntry
  consents.py                                # read consent for a customer
  audit.py                                   # append an audit entry
services/api/
  consent.py                                 # the AuthCheck factory, per-request cached
  middleware/audit.py                        # on_call_tool -> audit.append
tests/
  conftest.py                                # session-scoped container + engine, function-scoped rolled-back session
  test_store_models.py
  test_consent_enforcement.py                # filter AND call-time rejection
  test_audit_middleware.py
```

---

### Task 0: Database dependencies, settings and a local Postgres

**Files:**
- Modify: `pyproject.toml`, `services/api/settings.py`, `docker-compose.yml`
- Test: `tests/test_server_assembly.py`

- [ ] **Step 1: Add the dependencies**

In `pyproject.toml`, add to `[project].dependencies`:

```toml
    "sqlalchemy[asyncio]>=2.0.52,<3",
    "asyncpg>=0.31",
    "alembic>=1.20,<2",
```

and to the `dev` group in `[dependency-groups]`:

```toml
    "testcontainers[postgres]>=4.15",
```

`sqlalchemy[asyncio]` is required rather than plain `sqlalchemy`: the extra pulls `greenlet`, which the async engine needs and which is not currently installed.

- [ ] **Step 2: Install and confirm**

Run: `uv sync`
Then: `uv run python -c "import sqlalchemy, alembic, asyncpg; print(sqlalchemy.__version__, alembic.__version__)"`
Expected: prints `2.0.52 1.20.0` or later. `uv.lock` changes; commit it.

- [ ] **Step 3: Write the failing test for the new setting**

Add to `tests/test_server_assembly.py`:

```python
def test_settings_reads_the_database_url_from_the_environment(monkeypatch) -> None:
    monkeypatch.setenv("POSTERN_BACKEND_BASE_URL", "https://backend.test")
    monkeypatch.setenv("POSTERN_DATABASE_URL", "postgresql+asyncpg://u:p@db:5432/postern")
    monkeypatch.delenv("POSTERN_JWKS_URI", raising=False)
    monkeypatch.delenv("POSTERN_TOKEN_ISSUER", raising=False)
    assert Settings.from_env().database_url == "postgresql+asyncpg://u:p@db:5432/postern"


def test_settings_database_url_is_required() -> None:
    assert "database_url" in {f.name for f in dataclasses.fields(Settings)}
```

Add `import dataclasses` at the top of the test module if it is not already there.

- [ ] **Step 4: Run it to verify it fails**

Run: `uv run pytest tests/test_server_assembly.py -q -k database`
Expected: FAIL, `AttributeError: 'Settings' object has no attribute 'database_url'`

- [ ] **Step 5: Add the setting**

In `services/api/settings.py`, add the field to `Settings` immediately after `backend_base_url`:

```python
    database_url: str = "postgresql+asyncpg://postern:postern@localhost:5432/postern"
```

and in `from_env`, add:

```python
            database_url=os.environ.get(
                "POSTERN_DATABASE_URL",
                "postgresql+asyncpg://postern:postern@localhost:5432/postern",
            ),
```

A default is correct here rather than a required variable: the local compose stack and the test fixture both supply their own, and a missing database URL fails loudly on first connection with a clear asyncpg error rather than silently doing something wrong.

- [ ] **Step 6: Run it to verify it passes**

Run: `uv run pytest tests/test_server_assembly.py -q -k database`
Expected: PASS, 2 passed

- [ ] **Step 7: Add Postgres to the local stack**

In `docker-compose.yml`, add a service and wire the api to it:

```yaml
  db:
    image: postgres:17-alpine
    environment:
      POSTGRES_USER: postern
      POSTGRES_PASSWORD: postern
      POSTGRES_DB: postern
    ports: ["5432:5432"]
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U postern"]
      interval: 2s
      timeout: 3s
      retries: 15
```

Add to the `api` service's `environment`:

```yaml
      POSTERN_DATABASE_URL: postgresql+asyncpg://postern:postern@db:5432/postern
```

and to its `depends_on`:

```yaml
      db:
        condition: service_healthy
```

Check the existing `depends_on` syntax in the file first: if it is the short list form, convert it to the mapping form shown here so the health condition applies.

- [ ] **Step 8: Run the gates and commit**

Run: `make ci`
Expected: exit 0.

```bash
git add pyproject.toml uv.lock services/api/settings.py docker-compose.yml tests/test_server_assembly.py
git commit -m "build: add Postgres, SQLAlchemy async and Alembic dependencies"
```

---

### Task 1: The store package, engine and session factory

**Files:**
- Create: `packages/postern-core/src/postern_core/store/__init__.py`
- Create: `packages/postern-core/src/postern_core/store/base.py`
- Create: `packages/postern-core/src/postern_core/store/engine.py`
- Test: `tests/test_store_engine.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_store_engine.py
from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker

from postern_core.store.engine import Database


def test_database_exposes_an_engine_and_a_sessionmaker() -> None:
    db = Database("postgresql+asyncpg://u:p@localhost:5432/x")
    assert isinstance(db.engine, AsyncEngine)
    assert isinstance(db.sessionmaker, async_sessionmaker)


async def test_database_close_disposes_the_engine() -> None:
    db = Database("postgresql+asyncpg://u:p@localhost:5432/x")
    await db.close()
    assert db.engine.pool.status() is not None


def test_database_accepts_a_null_pool_for_tests() -> None:
    from sqlalchemy.pool import NullPool

    db = Database("postgresql+asyncpg://u:p@localhost:5432/x", null_pool=True)
    assert isinstance(db.engine.pool, NullPool)
```

None of these connect, so no container is needed: `create_async_engine` is lazy.

- [ ] **Step 2: Run it to verify it fails**

Run: `uv run pytest tests/test_store_engine.py -q`
Expected: FAIL, `ModuleNotFoundError: No module named 'postern_core.store'`

- [ ] **Step 3: Write `base.py`**

```python
# packages/postern-core/src/postern_core/store/base.py
"""Declarative base for every Postern table.

Kept separate from `models` so Alembic's `env.py` can import the metadata
without importing the models twice under different module paths.
"""

from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    """Base class for all ORM models."""
```

- [ ] **Step 4: Write `engine.py`**

```python
# packages/postern-core/src/postern_core/store/engine.py
"""Async engine and session factory.

One `Database` per process. The composition root builds it and closes it on
ASGI shutdown; nothing else may construct one, so connections are pooled
rather than opened per request.
"""

from types import TracebackType

from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool


class Database:
    def __init__(self, url: str, *, null_pool: bool = False) -> None:
        self.engine: AsyncEngine = create_async_engine(
            url,
            pool_pre_ping=True,
            poolclass=NullPool if null_pool else None,
        )
        self.sessionmaker: async_sessionmaker[AsyncSession] = async_sessionmaker(
            self.engine, expire_on_commit=False
        )

    async def close(self) -> None:
        await self.engine.dispose()

    async def __aenter__(self) -> "Database":
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.close()
```

`null_pool=True` exists for tests: pooled asyncpg connections raise `RuntimeError: Event loop is closed` if a test carries its own `loop_scope`, and `NullPool` survives that outright. Production uses the normal pool.

- [ ] **Step 5: Write the package `__init__.py`**

```python
# packages/postern-core/src/postern_core/store/__init__.py
"""Postgres persistence: consent records and the audit log."""
```

- [ ] **Step 6: Run it to verify it passes**

Run: `uv run pytest tests/test_store_engine.py -q`
Expected: PASS, 3 passed

- [ ] **Step 7: Commit**

```bash
git add packages/postern-core/src/postern_core/store tests/test_store_engine.py
git commit -m "feat(store): async engine and session factory"
```

---

### Task 2: Tables and the first migration

**Files:**
- Create: `packages/postern-core/src/postern_core/store/models.py`
- Create: `alembic.ini`, `migrations/env.py`, `migrations/versions/<generated>.py`
- Modify: `Makefile`
- Test: `tests/test_store_models.py`

- [x] **Step 1: Write the failing test**

```python
# tests/test_store_models.py
from postern_core.store.base import Base
from postern_core.store.models import AuditEntry, ConsentRecord


def test_both_tables_are_registered_on_the_metadata() -> None:
    assert set(Base.metadata.tables) == {"consents", "audit_log"}


def test_consent_is_unique_per_customer_and_domain() -> None:
    names = {c.name for c in ConsentRecord.__table__.constraints}
    assert "uq_consent_customer_domain" in names


def test_audit_entry_has_no_update_or_delete_helper() -> None:
    """Append-only by construction: the model exposes no mutation helpers."""
    public = {n for n in dir(AuditEntry) if not n.startswith("_")}
    assert not {n for n in public if n.startswith(("update", "delete"))}


def test_audit_arguments_column_is_jsonb() -> None:
    from sqlalchemy.dialects.postgresql import JSONB

    assert isinstance(AuditEntry.__table__.c.arguments.type, JSONB)
```

- [x] **Step 2: Run it to verify it fails**

Run: `uv run pytest tests/test_store_models.py -q`
Expected: FAIL, `ModuleNotFoundError: No module named 'postern_core.store.models'`

- [x] **Step 3: Write `models.py`**

```python
# packages/postern-core/src/postern_core/store/models.py
"""The two tables this plan owns (handoff §9).

`consents` records which banking domains a customer has authorized.
`audit_log` is append-only: the per-operation chain a regulator asks for.
Neither model exposes an update or delete helper, deliberately.
"""

from datetime import datetime
from typing import Any

from sqlalchemy import Boolean, DateTime, Index, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from postern_core.store.base import Base


class ConsentRecord(Base):
    __tablename__ = "consents"

    id: Mapped[int] = mapped_column(primary_key=True)
    customer_ref: Mapped[str] = mapped_column(String(64), index=True)
    domain: Mapped[str] = mapped_column(String(32))
    granted: Mapped[bool] = mapped_column(Boolean, default=False)
    granted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        UniqueConstraint("customer_ref", "domain", name="uq_consent_customer_domain"),
    )


class AuditEntry(Base):
    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(primary_key=True)
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    customer_ref: Mapped[str | None] = mapped_column(String(64), nullable=True)
    tool_name: Mapped[str] = mapped_column(String(64))
    arguments: Mapped[dict[str, Any]] = mapped_column(JSONB)
    outcome: Mapped[str] = mapped_column(String(16))
    detail: Mapped[str | None] = mapped_column(Text, nullable=True)

    __table_args__ = (Index("ix_audit_log_customer_at", "customer_ref", "at"),)
```

`outcome` is `"returned"` or `"raised"`, read from whether `call_next` raised, never from an `is_error` flag, for the reason in the verified facts.

- [x] **Step 4: Run it to verify it passes**

Run: `uv run pytest tests/test_store_models.py -q`
Expected: PASS, 4 passed

- [x] **Step 5: Initialise Alembic**

Run: `uv run alembic init --template async migrations`
Expected: creates `migrations/` and `alembic.ini` at the repo root.

- [x] **Step 6: Make the three edits to `migrations/env.py`**

Replace `target_metadata = None` with:

```python
import postern_core.store.models  # noqa: F401  registers the tables on the metadata
from postern_core.store.base import Base

target_metadata = Base.metadata
```

Immediately after `config = context.config`, add:

```python
import os

if (url := os.environ.get("POSTERN_DATABASE_URL")) is not None:
    config.set_main_option("sqlalchemy.url", url)
```

Replace the generated logging guard:

```python
if config.config_file_name is not None and os.path.exists(config.config_file_name):
    fileConfig(config.config_file_name)
```

**That third edit is not optional.** The generated template guards only on `is not None`, but `config_file_name` is the literal string `"alembic.ini"` even when that file is absent, so any configuration that does not keep an `alembic.ini` dies with `FileNotFoundError: alembic.ini doesn't exist`. Measured.

- [x] **Step 7: Generate and apply the migration against a real database**

```bash
docker compose up -d db
export POSTERN_DATABASE_URL=postgresql+asyncpg://postern:postern@localhost:5432/postern
uv run alembic revision --autogenerate -m "consents and audit log"
uv run alembic upgrade head
uv run alembic check
```

Expected: the revision names both tables (`Detected added table 'consents'`, `Detected added table 'audit_log'`), `upgrade` exits 0, and `check` prints `No new upgrade operations detected.` and exits 0.

Read the generated migration before committing it. Autogenerate is a draft, not an authority: confirm both tables, the unique constraint and both indexes are present and that nothing unexpected was added.

- [x] **Step 8 (revised): Add the drift gate as a standalone target, not a `make ci` prerequisite**

**Not implemented as originally written.** D6 above ("`alembic check` becomes a seventh `make ci` gate") was overridden during execution: `make ci` running fully offline in well under a second is the property that lets it run locally for free instead of against billed GitHub Actions minutes (see `CLAUDE.md`, `.github/workflows/ci.yml`'s own header comment). Adding `migrations` to the `ci` chain would make that gate require a running Postgres on every commit on every machine, which trades a real, load-bearing property (offline, sub-second, runs anywhere) for a gate that already runs for free somewhere else.

Instead:

In the `Makefile`, add a target that is **not** in the `ci` prerequisite list:

```make
migrations:
	POSTERN_DATABASE_URL=$${POSTERN_DATABASE_URL:-postgresql+asyncpg://postern:postern@localhost:5432/postern} uv run alembic check
```

documented inline as needing a reachable database and required before committing any change to `packages/postern-core/src/postern_core/store/models.py`.

The same check runs in `.github/workflows/ci.yml`, which stays `workflow_dispatch`-only, as an extra step after `make test` against a `postgres:17-alpine` service container (free on a manually dispatched run):

```yaml
      - run: uv run alembic upgrade head
      - run: make migrations
```

`alembic check` exits 1 (measured: 255 from the `alembic` CLI wrapper) when a model has changed without a migration, naming the exact drifted column, and exits 0 again once the migration or the model change is reconciled. Both directions verified against a real container as part of Task 2. `make ci` was confirmed to still exit 0, in ~0.9-1.5s, with the database container stopped.

- [x] **Step 9: Run the gates and commit**

Run: `make ci`
Expected: exit 0.

```bash
git add packages/postern-core/src/postern_core/store/models.py alembic.ini migrations Makefile .github/workflows/ci.yml tests/test_store_models.py docs/superpowers/plans/postern-persistence-consent-audit-2026-09-14.md
git commit -m "feat(store): consents and audit_log tables with an alembic drift gate"
```

`.github/workflows/ci.yml` is included because Step 8 was revised to add the drift check there instead of to `make ci`; the plan file itself is included because Step 8 and D6 above were corrected to match.

---

### Task 3: Test fixtures and the consent repository

**Files:**
- Modify: `tests/conftest.py`
- Create: `packages/postern-core/src/postern_core/store/consents.py`
- Test: `tests/test_store_consents.py`

- [x] **Step 1: Add the database fixtures to `tests/conftest.py`**

```python
import os

import pytest
import pytest_asyncio
from alembic import command
from alembic.config import Config
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from testcontainers.community.postgres import PostgresContainer

from postern_core.store.engine import Database


@pytest.fixture(scope="session")
def pg_url() -> str:
    """SYNC on purpose.

    The async Alembic env.py ends in asyncio.run(), so calling
    command.upgrade from inside a coroutine raises
    `RuntimeError: asyncio.run() cannot be called from a running event loop`.
    """
    with PostgresContainer("postgres:17-alpine", driver="asyncpg") as pg:
        url = pg.get_connection_url()
        os.environ["POSTERN_DATABASE_URL"] = url
        cfg = Config("alembic.ini")
        cfg.set_main_option("sqlalchemy.url", url)
        command.upgrade(cfg, "head")
        yield url


@pytest_asyncio.fixture(scope="session")
async def database(pg_url: str) -> Database:
    db = Database(pg_url, null_pool=True)
    yield db
    await db.close()


@pytest_asyncio.fixture
async def session(database: Database) -> AsyncSession:
    """Function-scoped and rolled back, so tests cannot see each other's rows."""
    async with database.engine.connect() as conn:
        trans = await conn.begin()
        maker = async_sessionmaker(bind=conn, expire_on_commit=False)
        async with maker() as s:
            yield s
        await trans.rollback()
```

`driver="asyncpg"` must be passed explicitly: `PostgresContainer` defaults to `psycopg2` and would hand back a sync URL. `null_pool=True` guards against a future test carrying its own `loop_scope` marker, which otherwise raises `RuntimeError: Event loop is closed` on a pooled asyncpg connection.

**Revised beyond this snippet, per D7 above:** `pg_url` opens with a `docker.from_env().ping()` guarded by `except DockerException: pytest.skip(...)`, before constructing `PostgresContainer` at all. Without it, a machine with no Docker running gets a 15-frame `docker.errors.DockerException` traceback, once per test that depends on `session` (measured: 7 traceback blocks, `DOCKER_HOST` pointed at a nonexistent socket). With it, the same run produces 7 clean skips in 0.01s, each carrying its own reason. This needed `types-docker` added to the dev dependency group for `mypy --strict` to accept the `docker` import (`tests/conftest.py`, `pyproject.toml`, `uv.lock`).

- [x] **Step 2: Write the failing test**

```python
# tests/test_store_consents.py
from datetime import UTC, datetime, timedelta

from postern_core.identity import CustomerRef
from postern_core.store import consents
from postern_core.store.models import ConsentRecord

CUST = CustomerRef(value="cust_7f3a")
OTHER = CustomerRef(value="cust_9b21")


async def _grant(session, customer: str, domain: str, *, expires_at=None, granted=True) -> None:
    session.add(
        ConsentRecord(
            customer_ref=customer,
            domain=domain,
            granted=granted,
            granted_at=datetime.now(UTC),
            expires_at=expires_at,
        )
    )
    await session.flush()


async def test_granted_domains_returns_only_this_customers_rows(session) -> None:
    await _grant(session, CUST.value, "accounts")
    await _grant(session, OTHER.value, "payments")
    assert await consents.granted_domains(session, CUST) == {"accounts"}


async def test_an_ungranted_row_is_not_returned(session) -> None:
    await _grant(session, CUST.value, "payments", granted=False)
    assert await consents.granted_domains(session, CUST) == set()


async def test_an_expired_row_is_treated_as_absent(session) -> None:
    past = datetime.now(UTC) - timedelta(days=1)
    await _grant(session, CUST.value, "cards", expires_at=past)
    assert await consents.granted_domains(session, CUST) == set()


async def test_a_future_expiry_is_still_granted(session) -> None:
    future = datetime.now(UTC) + timedelta(days=30)
    await _grant(session, CUST.value, "cards", expires_at=future)
    assert await consents.granted_domains(session, CUST) == {"cards"}


async def test_a_null_expiry_never_expires(session) -> None:
    await _grant(session, CUST.value, "transactions", expires_at=None)
    assert await consents.granted_domains(session, CUST) == {"transactions"}


async def test_a_customer_with_no_rows_has_no_consent(session) -> None:
    assert await consents.granted_domains(session, CUST) == set()
```

**Extended beyond this snippet:** a seventh test, `test_rollback_isolation_row_from_other_test_is_not_visible`, asserting `CUST` has no granted domains — the direct proof that the `session` fixture's rollback isolates tests from each other, run alongside the row-inserting test above in both collection orders (both pass; see Task 3's completion note after Step 6).

- [x] **Step 3: Run it to verify it fails**

Run: `uv run pytest tests/test_store_consents.py -q`
Expected: FAIL, `ModuleNotFoundError: No module named 'postern_core.store.consents'`. Docker must be running; the fixture starts a real Postgres 17 container.

Actual, verified:

```
ImportError while importing test module '.../tests/test_store_consents.py'.
tests/test_store_consents.py:13: in <module>
    from postern_core.store import consents
E   ImportError: cannot import name 'consents' from 'postern_core.store'
1 error in 0.05s
```

- [x] **Step 4: Write `consents.py`**

```python
# packages/postern-core/src/postern_core/store/consents.py
"""Reading consent.

Granting consent belongs to the device-grant flow (Plan 4). This module only
reads, and treats an expired row as absent rather than as an error: expiry
renewal is a flow, not a failure.
"""

from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from postern_core.identity import CustomerRef
from postern_core.store.models import ConsentRecord


async def granted_domains(session: AsyncSession, customer: CustomerRef) -> set[str]:
    """The domains this customer has currently consented to."""
    now = datetime.now(UTC)
    stmt = select(ConsentRecord.domain).where(
        ConsentRecord.customer_ref == customer.value,
        ConsentRecord.granted.is_(True),
        (ConsentRecord.expires_at.is_(None)) | (ConsentRecord.expires_at > now),
    )
    rows = await session.execute(stmt)
    return set(rows.scalars().all())
```

- [x] **Step 5: Run it to verify it passes**

Run: `uv run pytest tests/test_store_consents.py -q`
Expected: PASS, 6 passed. Actual: **7 passed** in 1.62-1.75s (the seventh is the rollback-isolation test added above); confirmed stable across three consecutive runs and in reverse collection order.

Each of the three filters in `granted_domains` (customer, `granted is True`, expiry) was broken one at a time and confirmed to fail a specific test, not a vague one:

- Dropping `ConsentRecord.customer_ref == customer.value` made `test_granted_domains_returns_only_this_customers_rows` fail with `{'accounts', 'payments'} == {'accounts'}` — `OTHER`'s `payments` grant leaked into `CUST`'s result.
- Dropping `ConsentRecord.granted.is_(True)` made `test_an_ungranted_row_is_not_returned` fail with `{'payments'} == set()` — a revoked row was returned as granted.
- Dropping the expiry clause made `test_an_expired_row_is_treated_as_absent` fail with `{'cards'} == set()` — a row expired a day ago was returned as current.

Each break was reverted before moving to the next; the final implementation is byte-for-byte the code block in Step 4.

- [x] **Step 6: Commit**

```bash
git add tests/conftest.py tests/test_store_consents.py packages/postern-core/src/postern_core/store/consents.py Makefile .github/workflows/ci.yml pyproject.toml uv.lock docs/superpowers/plans/postern-persistence-consent-audit-2026-09-14.md
git commit -m "feat(store): read consent, treating an expired row as absent"
```

`Makefile` and `.github/workflows/ci.yml` are included because D7 above changes what `make ci` and the workflow's comments claim about `make ci` being fully offline. `pyproject.toml` and `uv.lock` are included for the `types-docker` dev dependency the Docker-reachability skip guard needs to pass `mypy --strict`. The plan file is included because Step 1, Step 2, Step 3, Step 5 and the decision log were corrected to match what was actually built (D7).

---

### Task 4: Consent enforcement, the load-bearing task

**Files:**
- Create: `services/api/consent.py`
- Modify: `services/api/server.py`, `services/api/tools/accounts.py`, `services/api/tools/transactions.py`, `services/api/tools/cards.py`
- Test: `tests/test_consent_enforcement.py`

**Read this before writing code.** The obvious implementation, filtering `tools/list` in an `on_list_tools` middleware, is NOT enforcement. It was measured: a token filtered out of a tool called it by name anyway and got `isError: false`. The handoff's phrasing ("the payment tools should not appear in `tools/list` at all") describes the visible symptom of the control, not the control. FastMCP's per-tool `auth=` check does both, in one declaration, and its denial reads as `Unknown tool` so it discloses nothing about what exists.

These tests must run over HTTP, not through the in-process `Client`: `get_access_token()` returns `None` in-process, so an in-process test of a consent check would pass vacuously no matter what the check does.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_consent_enforcement.py
"""Consent must FILTER the catalogue and REJECT the call.

Filtering alone is not enforcement: a hidden tool is still callable by name.
Every test here runs over HTTP because get_access_token() is None under the
in-process Client, which would make these assertions pass vacuously.
"""

import json
from datetime import UTC, datetime

import httpx2
import pytest
from fastmcp.server.auth.providers.jwt import JWTVerifier, RSAKeyPair

from postern_core.store.models import ConsentRecord
from services.api.main import create_app
from services.api.settings import Settings

ISSUER = "https://postern-test.invalid"
AUDIENCE = "postern"
_META = {
    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
    "io.modelcontextprotocol/clientCapabilities": {},
}


@pytest.fixture(scope="session")
def key_pair() -> RSAKeyPair:
    return RSAKeyPair.generate()


def token_for(key_pair: RSAKeyPair, subject: str) -> str:
    return key_pair.create_token(subject=subject, issuer=ISSUER, audience=AUDIENCE)


async def seed(session, customer: str, *domains: str) -> None:
    for domain in domains:
        session.add(
            ConsentRecord(
                customer_ref=customer,
                domain=domain,
                granted=True,
                granted_at=datetime.now(UTC),
                expires_at=None,
            )
        )
    await session.commit()


def app_for(pg_url: str, key_pair: RSAKeyPair, backend_handler):
    settings = Settings(
        backend_base_url="https://backend.test",
        database_url=pg_url,
        customer_jwks_uri=None,
        customer_token_issuer=None,
        allow_stub_token_minter=True,
    )
    verifier = JWTVerifier(public_key=key_pair.public_key, issuer=ISSUER, audience=AUDIENCE)
    return create_app(
        settings,
        transport=httpx2.MockTransport(backend_handler),
        auth_override=verifier,
    )


async def rpc(app, token: str, method: str, params: dict) -> dict:
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        "Authorization": f"Bearer {token}",
        "Mcp-Method": method,
    }
    if method == "tools/call":
        headers["Mcp-Name"] = params["name"]
    body = {"jsonrpc": "2.0", "id": 1, "method": method, "params": {**params, "_meta": _META}}
    async with httpx2.AsyncClient(
        transport=httpx2.ASGITransport(app=app), base_url="http://t"
    ) as c:
        async with app.router.lifespan_context(app):
            r = await c.post("/mcp", headers=headers, json=body)
    return json.loads(r.text)


def backend(request: httpx2.Request) -> httpx2.Response:
    return httpx2.Response(200, json={"cards": [], "accounts": [], "transactions": []})


async def test_catalogue_is_filtered_by_consent(pg_url, key_pair, session) -> None:
    await seed(session, "cust_7f3a", "accounts")
    app = app_for(pg_url, key_pair, backend)
    out = await rpc(app, token_for(key_pair, "cust_7f3a"), "tools/list", {})
    names = {t["name"] for t in out["result"]["tools"]}
    assert "accounts.list" in names
    assert "cards.list" not in names


async def test_a_filtered_tool_is_also_uncallable(pg_url, key_pair, session) -> None:
    """The one that matters. A hidden tool must not be callable by name."""
    await seed(session, "cust_7f3a", "accounts")
    app = app_for(pg_url, key_pair, backend)
    out = await rpc(
        app,
        token_for(key_pair, "cust_7f3a"),
        "tools/call",
        {"name": "cards.list", "arguments": {}},
    )
    assert out["result"]["isError"] is True
    assert "cards.list" not in json.dumps(out["result"]).replace("Unknown tool: 'cards.list'", "")


async def test_a_consented_tool_is_callable(pg_url, key_pair, session) -> None:
    await seed(session, "cust_7f3a", "accounts")
    app = app_for(pg_url, key_pair, backend)
    out = await rpc(
        app,
        token_for(key_pair, "cust_7f3a"),
        "tools/call",
        {"name": "accounts.list", "arguments": {}},
    )
    assert out["result"]["isError"] is False


async def test_two_customers_see_different_catalogues(pg_url, key_pair, session) -> None:
    await seed(session, "cust_7f3a", "accounts")
    await seed(session, "cust_9b21", "accounts", "cards")
    app = app_for(pg_url, key_pair, backend)
    a = await rpc(app, token_for(key_pair, "cust_7f3a"), "tools/list", {})
    b = await rpc(app, token_for(key_pair, "cust_9b21"), "tools/list", {})
    assert {t["name"] for t in a["result"]["tools"]} != {t["name"] for t in b["result"]["tools"]}


async def test_a_customer_with_no_consent_sees_only_the_bootstrap_tool(
    pg_url, key_pair, session
) -> None:
    app = app_for(pg_url, key_pair, backend)
    out = await rpc(app, token_for(key_pair, "cust_7f3a"), "tools/list", {})
    assert {t["name"] for t in out["result"]["tools"]} == {"banking_start_session"}


async def test_a_malformed_subject_yields_an_empty_catalogue_not_an_error(
    pg_url, key_pair, session
) -> None:
    """An uncaught exception in the auth check becomes JSON-RPC -32603."""
    out = await rpc(
        app_for(pg_url, key_pair, backend),
        token_for(key_pair, "ES9121000418450200051332"),
        "tools/list",
        {},
    )
    assert "error" not in out
    assert out["result"]["tools"] == []
```

`banking_start_session` carries no consent requirement on purpose: it is how a customer with no consent learns what to authorize, and it returns only their own account labels and the consent state itself.

- [ ] **Step 2: Run it to verify it fails**

Run: `uv run pytest tests/test_consent_enforcement.py -q`
Expected: FAIL, `ModuleNotFoundError: No module named 'services.api.consent'`

- [ ] **Step 3: Write `services/api/consent.py`**

```python
# services/api/consent.py
"""Consent as a per-tool authorization check.

FastMCP's `auth=` parameter takes an AuthCheck, which may be async
(fastmcp/utilities/authorization.py:47 and :230-250). FastMCP applies it in
BOTH places: `list_tools` filters the catalogue with it, and `_get_tool`
returns None when it fails, so the call reports `Unknown tool`.

That pairing is the point. Filtering `tools/list` alone is NOT enforcement:
a hidden tool remains callable by name. Measured, 2026-09-14.

The check is cached per request because a `tools/call` carrying non-empty
arguments triggers a full internal `tools/list` dispatch to validate
Mcp-Param headers (mcp/server/_streamable_http_modern.py:285-359), so an
uncached lookup runs twice for every real call.
"""

from collections.abc import Awaitable, Callable

from fastmcp.server.auth import AuthContext
from fastmcp.server.dependencies import get_http_request
from pydantic import ValidationError

from postern_core.identity import CustomerRef
from postern_core.store import consents
from postern_core.store.engine import Database

_CACHE_ATTR = "postern_consent_domains"


def _customer(ctx: AuthContext) -> CustomerRef | None:
    token = ctx.token
    subject = token.claims.get("sub") if token is not None else None
    if not isinstance(subject, str):
        return None
    try:
        return CustomerRef(value=subject)
    except ValidationError:
        return None


async def _domains(db: Database, customer: CustomerRef) -> set[str]:
    request = None
    try:
        request = get_http_request()
    except Exception:
        request = None

    if request is not None:
        cached = getattr(request.state, _CACHE_ATTR, None)
        if isinstance(cached, dict) and customer.value in cached:
            return cached[customer.value]

    async with db.sessionmaker() as session:
        granted = await consents.granted_domains(session, customer)

    if request is not None:
        cache = getattr(request.state, _CACHE_ATTR, None)
        if not isinstance(cache, dict):
            cache = {}
            setattr(request.state, _CACHE_ATTR, cache)
        cache[customer.value] = granted
    return granted


def consent_for(domain: str, db: Database) -> Callable[[AuthContext], Awaitable[bool]]:
    """An AuthCheck granting access to `domain` only if the customer consented."""

    async def check(ctx: AuthContext) -> bool:
        customer = _customer(ctx)
        if customer is None:
            return False
        return domain in await _domains(db, customer)

    return check
```

Returning `False` rather than raising is deliberate: an uncaught exception in this call stack surfaces as JSON-RPC `-32603`, so a malformed token subject would turn every `tools/list` into an internal error instead of an empty catalogue.

- [ ] **Step 4: Attach the check to each tool**

In `services/api/tools/accounts.py`, `transactions.py` and `cards.py`, thread a `check` argument through `register` and pass it to each `@mcp.tool` call. For accounts:

```python
def register(
    mcp: FastMCP,
    resolver: CustomerResolver,
    backend: BackendReader,
    check: Callable[[AuthContext], Awaitable[bool]],
) -> None:
    @mcp.tool(name="accounts.list", annotations=_READ, auth=check)
    async def accounts_list() -> list[Account]:
        ...
```

Apply the same shape to `accounts.get_balance`, `transactions.list` and `cards.list`. Do NOT attach a check to `banking_start_session`.

In `services/api/server.py`, `build_server` takes a new keyword-only `db: Database | None = None` and passes `consent_for("accounts", db)` and so on to each `register`. When `db is None`, pass a check that returns `True`, so every existing test that builds a server without a database keeps working unchanged and the consent tests are the ones that exercise the real path.

Verify the `auth=` keyword exists on the installed `FastMCP.tool` before writing all four: `uv run python -c "import inspect, fastmcp; print('auth' in inspect.signature(fastmcp.FastMCP.tool).parameters)"` must print `True`.

- [ ] **Step 5: Run it to verify it passes**

Run: `uv run pytest tests/test_consent_enforcement.py -q`
Expected: PASS, 6 passed

- [ ] **Step 6: Prove the pairing by breaking it**

Temporarily change `consent_for` to always return `True` and re-run. `test_catalogue_is_filtered_by_consent` and `test_a_filtered_tool_is_also_uncallable` must BOTH fail. Restore, re-run, confirm green, and paste both outputs. A consent check nobody has watched deny anything is not a control.

- [ ] **Step 7: Run the gates and commit**

Run: `make ci`
Expected: exit 0.

```bash
git add services/api/consent.py services/api/server.py services/api/tools tests/test_consent_enforcement.py
git commit -m "feat(api): consent filters the catalogue and rejects the call"
```

---

### Task 5: The audit log

**Files:**
- Create: `packages/postern-core/src/postern_core/store/audit.py`
- Create: `services/api/middleware/__init__.py`, `services/api/middleware/audit.py`
- Test: `tests/test_audit_middleware.py`

Handoff §9: the audit chain is "which tool the agent called, with what arguments". Two facts from the verified list shape this task. Failures reach `on_call_tool` as **raised exceptions**, never as `ToolResult(is_error=True)`, so a hook reading a result flag records zero failures. And `ValidationError` carries the offending input value, which is the masking leak path `CLAUDE.md` documents, so nothing derived from an exception message may be persisted.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_audit_middleware.py
import httpx2
import pytest
from fastmcp.client import Client
from fastmcp.exceptions import ToolError
from sqlalchemy import select

from postern_core.store.models import AuditEntry
from services.api.middleware.audit import AuditMiddleware


async def rows(session) -> list[AuditEntry]:
    result = await session.execute(select(AuditEntry).order_by(AuditEntry.id))
    return list(result.scalars().all())


async def test_a_successful_call_is_recorded(audit_server, session) -> None:
    async with Client(transport=audit_server) as c:
        await c.call_tool("ok_tool", {"amount": 50})
    entries = await rows(session)
    assert [(e.tool_name, e.outcome) for e in entries] == [("ok_tool", "returned")]
    assert entries[0].arguments == {"amount": 50}


async def test_a_failing_call_is_recorded(audit_server, session) -> None:
    """The one that matters: failures arrive as raised exceptions, not a flag."""
    async with Client(transport=audit_server) as c:
        await c.call_tool("boom_tool", {}, raise_on_error=False)
    entries = await rows(session)
    assert [(e.tool_name, e.outcome) for e in entries] == [("boom_tool", "raised")]


async def test_the_detail_records_the_exception_type_not_its_message(
    audit_server, session
) -> None:
    """A ValidationError message carries the raw offending value."""
    async with Client(transport=audit_server) as c:
        await c.call_tool("leaky_tool", {"pan": "4111111111114417"}, raise_on_error=False)
    entry = (await rows(session))[0]
    assert "4111111111114417" not in (entry.detail or "")
    assert entry.detail in {"ToolError", "ValidationError", "NotFoundError"}


async def test_arguments_are_scrubbed_before_they_are_stored(audit_server, session) -> None:
    async with Client(transport=audit_server) as c:
        await c.call_tool("ok_tool", {"amount": 1, "memo": "IBAN ES9121000418450200051332"})
    entry = (await rows(session))[0]
    assert "ES9121000418450200051332" not in str(entry.arguments)
    assert "ES•• •••• 1332" in str(entry.arguments)


async def test_the_exception_still_propagates_after_being_recorded(
    audit_server, session
) -> None:
    async with Client(transport=audit_server) as c:
        result = await c.call_tool("boom_tool", {}, raise_on_error=False)
    assert result.is_error is True
    assert len(await rows(session)) == 1
```

Add this fixture to `tests/conftest.py`:

```python
@pytest.fixture
def audit_server(database):
    from fastmcp import FastMCP

    from services.api.middleware.audit import AuditMiddleware

    mcp = FastMCP(name="audit-test")
    mcp.add_middleware(AuditMiddleware(database))

    @mcp.tool
    async def ok_tool(amount: int, memo: str = "") -> str:
        return f"ok {amount}"

    @mcp.tool
    async def boom_tool() -> str:
        raise ValueError("internal detail")

    @mcp.tool
    async def leaky_tool(pan: int) -> str:
        return "unreachable"

    return mcp
```

`leaky_tool` takes an `int` so passing a PAN string triggers argument coercion and a `ValidationError`, which is the exception type that carries the raw value.

- [ ] **Step 2: Run it to verify it fails**

Run: `uv run pytest tests/test_audit_middleware.py -q`
Expected: FAIL, `ModuleNotFoundError: No module named 'services.api.middleware'`

- [ ] **Step 3: Write `store/audit.py`**

```python
# packages/postern-core/src/postern_core/store/audit.py
"""Appending to the audit log.

Append-only by construction: this module exposes no update and no delete.
"""

from datetime import datetime
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from postern_core.store.models import AuditEntry


async def append(
    session: AsyncSession,
    *,
    at: datetime,
    customer_ref: str | None,
    tool_name: str,
    arguments: dict[str, Any],
    outcome: str,
    detail: str | None,
) -> None:
    session.add(
        AuditEntry(
            at=at,
            customer_ref=customer_ref,
            tool_name=tool_name,
            arguments=arguments,
            outcome=outcome,
            detail=detail,
        )
    )
    await session.commit()
```

- [ ] **Step 4: Write the middleware**

```python
# services/api/middleware/audit.py
"""One audit row per tool call, success or failure.

Failures reach `on_call_tool` as RAISED EXCEPTIONS: the `isError: true`
envelope is built above the middleware chain, so a hook inspecting
`result.is_error` records zero failures. Measured, 2026-09-14.

`detail` records the exception TYPE and never its message: a
`pydantic.ValidationError` message embeds the raw offending value, which is
the leak path CLAUDE.md's hard rule describes, and an audit table is a
long-lived store.
"""

from typing import Any

from fastmcp.server.dependencies import get_access_token
from fastmcp.server.middleware import Middleware, MiddlewareContext
from pydantic import TypeAdapter

from postern_core.domain.masking import FreeText
from postern_core.store import audit
from postern_core.store.engine import Database

_FREE_TEXT = TypeAdapter(FreeText)


def _scrub(value: Any) -> Any:
    """Redact PAN- and IBAN-shaped substrings anywhere in the argument tree."""
    if isinstance(value, str):
        return _FREE_TEXT.validate_python(value)
    if isinstance(value, dict):
        return {k: _scrub(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_scrub(v) for v in value]
    return value


class AuditMiddleware(Middleware):
    def __init__(self, db: Database) -> None:
        self.db = db

    async def on_call_tool(self, context: MiddlewareContext, call_next):  # type: ignore[no-untyped-def]
        name = context.message.name
        arguments = _scrub(dict(context.message.arguments or {}))
        token = get_access_token()
        subject = token.claims.get("sub") if token is not None else None
        customer = subject if isinstance(subject, str) else None
        at = context.timestamp

        try:
            result = await call_next(context)
        except Exception as exc:
            await self._write(at, customer, name, arguments, "raised", type(exc).__name__)
            raise
        await self._write(at, customer, name, arguments, "returned", None)
        return result

    async def _write(
        self,
        at: Any,
        customer: str | None,
        name: str,
        arguments: dict[str, Any],
        outcome: str,
        detail: str | None,
    ) -> None:
        async with self.db.sessionmaker() as session:
            await audit.append(
                session,
                at=at,
                customer_ref=customer,
                tool_name=name,
                arguments=arguments,
                outcome=outcome,
                detail=detail,
            )
```

Create `services/api/middleware/__init__.py` containing only a docstring.

- [ ] **Step 5: Run it to verify it passes**

Run: `uv run pytest tests/test_audit_middleware.py -q`
Expected: PASS, 5 passed

- [ ] **Step 6: Prove the failure path is real**

Temporarily replace the `try`/`except` with a plain `result = await call_next(context)` and a single success write. `test_a_failing_call_is_recorded` must fail with zero rows. Restore and paste both outputs. This is the exact defect the verified facts warn about, so it must be seen once.

- [ ] **Step 7: Commit**

```bash
git add packages/postern-core/src/postern_core/store/audit.py services/api/middleware tests/test_audit_middleware.py tests/conftest.py
git commit -m "feat(api): audit every tool call, including the ones that fail"
```

---

### Task 6: Wire the database into the composition root

**Files:**
- Modify: `services/api/main.py`, `services/api/server.py`
- Test: `tests/test_asgi_app.py`

- [ ] **Step 1: Write the failing test**

Add to `tests/test_asgi_app.py`:

```python
def test_create_app_builds_a_database_from_settings() -> None:
    app = create_app(Settings.for_testing(), resolver=lambda: TEST_CUSTOMER)
    assert getattr(app.state, "postern_database", None) is not None


def test_create_app_installs_the_audit_middleware() -> None:
    from services.api.middleware.audit import AuditMiddleware

    app = create_app(Settings.for_testing(), resolver=lambda: TEST_CUSTOMER)
    server = app.state.postern_server
    assert any(isinstance(m, AuditMiddleware) for m in server.middleware)


async def test_the_database_is_closed_on_shutdown() -> None:
    app = create_app(Settings.for_testing(), resolver=lambda: TEST_CUSTOMER)
    db = app.state.postern_database
    async with app.router.lifespan_context(app):
        pass
    assert db.engine.pool.status() is not None
```

Check how the existing tests reach the server object before writing these: if `create_app` does not already stash it, add `app.state.postern_server` and `app.state.postern_database` in `create_app` as part of this task, since the lifespan hook needs the database anyway.

- [ ] **Step 2: Run it to verify it fails**

Run: `uv run pytest tests/test_asgi_app.py -q -k database`
Expected: FAIL, `AssertionError` on the missing `app.state.postern_database`.

- [ ] **Step 3: Wire it**

In `create_app`, build the `Database` from `settings.database_url`, pass it to `build_server(..., db=db)`, register `AuditMiddleware(db)` on the server, stash both on `app.state`, and extend the existing lifespan wrapper (the one Task 12 added to close the backend client) to also `await db.close()`.

The existing wrapper reads `app.router.lifespan_context`, wraps it and writes it back, so FastMCP's own session-manager lifespan still runs. Add the database close alongside the backend close in the same wrapper; do NOT add a second wrapper.

- [ ] **Step 4: Run it to verify it passes**

Run: `uv run pytest tests/test_asgi_app.py -q`
Expected: PASS, all tests in the file.

- [ ] **Step 5: Run the gates and commit**

Run: `make ci`
Expected: exit 0.

```bash
git add services/api/main.py services/api/server.py tests/test_asgi_app.py
git commit -m "feat(api): build the database in the composition root and close it on shutdown"
```

---

### Task 7: Verify the whole thing against the running stack

**Files:**
- Create: `docs/verification/<today>-consent-and-audit.md`

- [ ] **Step 1: Start the stack**

```bash
docker compose up -d --build
```

Expected: `db`, `backend-stub` and `api` all start, `db` reporting healthy.

- [ ] **Step 2: Apply migrations against the running database**

```bash
POSTERN_DATABASE_URL=postgresql+asyncpg://postern:postern@localhost:5432/postern uv run alembic upgrade head
```

Expected: exit 0.

- [ ] **Step 3: Seed consent for the stub customer**

The stub mints tokens with subject `cust_7f3a`. Insert one consent row for `accounts` only:

```bash
docker compose exec -T db psql -U postern -d postern -c \
  "INSERT INTO consents (customer_ref, domain, granted, granted_at, expires_at) VALUES ('cust_7f3a','accounts',true,now(),null);"
```

- [ ] **Step 4: Prove the catalogue is filtered**

Mint a token from `http://localhost:8081/mint-token`, then call `tools/list` and record the tool names. `accounts.list` and `banking_start_session` must be present; `cards.list` and `transactions.list` must be absent.

- [ ] **Step 5: Prove the hidden tool is uncallable**

Call `tools/call` for `cards.list` with the same token. Record the response. It must report an error and must not execute.

- [ ] **Step 6: Prove the audit rows exist**

```bash
docker compose exec -T db psql -U postern -d postern -c \
  "SELECT tool_name, outcome, detail, customer_ref FROM audit_log ORDER BY id;"
```

Expected: one `returned` row for the successful call and one `raised` row for the denied one, both with `customer_ref` `cust_7f3a`. Confirm no raw PAN or IBAN appears in the `arguments` column.

- [ ] **Step 7: Write the verification record and tear down**

Record every command and its real output in `docs/verification/<today>-consent-and-audit.md`, stating plainly which checks were run over HTTP and which by querying the database directly. Then `docker compose down`.

- [ ] **Step 8: Commit**

```bash
git add docs/verification
git commit -m "docs: verify consent filtering, enforcement and the audit log against the running stack"
```

---

## What this plan deliberately does not establish

| Not established | Why it matters | Lands in |
|---|---|---|
| Granting consent | Nothing here creates a consent row for a real customer; the device-grant flow does | Plan 4 |
| Consent revocation latency | With `stateless_http=True` there is no `notifications/tools/list_changed` path in FastMCP 4.0.3, so a revoked consent stays visible in a client's cached catalogue until `ttlMs` expires | unscheduled |
| Whether real clients honour `cacheScope` | Honouring is client opt-in; treat it as unhonoured until measured against each vendor | out of repo |
| Expiry renewal and the 180-day RTS re-authentication | Needs the device-grant flow | Plan 4 |
| Audit chain for writes | There is no write path yet; the chain a regulator asks for ends at execution, which does not exist | Plans 5 and 6 |
| Distinguishing a denied call from a typo in the audit log | `NotFoundError` fires for both; telling them apart means recording the consent decision inside the check | unscheduled |

## Self-review

- **Spec coverage.** Handoff §9's `consents` and `audit_log` are Tasks 2, 3 and 5. §6.1's consent-scoped tool surface is Task 4. §3.4's `cacheScope` is unchanged and its limits are recorded rather than re-litigated. The `challenges` and `tokens` tables from §9 are explicitly deferred with a reason.
- **Placeholders.** None. Every code step carries its code. The one genuinely unknown value, the shape of `create_app`'s existing lifespan wrapper, is handled by telling the implementer to read it first rather than guessing at it in a code block.
- **Type consistency.** `Database.sessionmaker`, `consents.granted_domains(session, customer) -> set[str]`, `audit.append(session, *, at, customer_ref, tool_name, arguments, outcome, detail)`, and `consent_for(domain, db) -> Callable[[AuthContext], Awaitable[bool]]` are used identically everywhere they appear.
- **Known risk in the plan itself.** Task 4 assumes `FastMCP.tool` accepts an `auth=` keyword. That was verified for per-tool checks in this FastMCP version, but Step 4 includes a one-line command to re-confirm it on the installed package before four files are edited against it. If it is absent, the fallback is `AuthMiddleware(auth=...)`, which the research confirmed applies the same check in both `on_list_tools` and `on_call_tool`.

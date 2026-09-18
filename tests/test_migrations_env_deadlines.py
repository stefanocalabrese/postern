"""Migrations inherit none of `Database`'s deadlines, on purpose.

`Database.__init__` puts asyncpg's `timeout` and `command_timeout` on every
connection the application opens, so a statement that stalls fails the call
instead of parking a worker. `migrations/env.py` builds its OWN engine with
`async_engine_from_config` and constructs no `Database`, so an `ALTER TABLE`
rewriting a large table keeps an unbounded statement rather than being killed
at 3.0 seconds with the table half-rewritten. That is the right default for a
migration and the wrong one for a request, which is why the two paths build
engines separately.

Until this file, that property lived in `61934d1`'s commit message and
nowhere else; `docs/verification/2026-09-17-query-stall-deadline.md` records
it under what the measurement does NOT establish, as "read, not tested". A
timeout added to env.py -- by someone copying `Database`'s `connect_args`
across, which is the realistic way it happens -- would break a long migration
in production and no gate would say so first.

What this asserts is the real engine, not a re-reading of the source.
`ScriptDirectory.run_env()` execs this repo's actual `migrations/env.py`,
with `async_engine_from_config` wrapped so the engine env.py builds is handed
back to the test. A `do_connect` listener then reads the FINAL, merged driver
parameters and raises before a socket opens, the technique
`tests/test_store_timeouts.py::_driver_connect_kwargs` uses for the same
reason: that merge point is the only place where a `connect_args` keyword, a
URL query string and an `alembic.ini` entry all become visible as one dict.
No Postgres, no Docker, no migration runs.

The `Config` here is built in memory rather than from `alembic.ini`, which
leaves `config.config_file_name` at `None` and makes env.py's `fileConfig`
guard take its False branch. That is deliberate: `fileConfig` rewrites
process-wide logging state for the rest of the pytest session, and
`tests/test_migrations_env_logging.py` spawns a subprocess specifically to
keep it out of this one. Nothing in the engine env.py builds depends on
logging having been configured.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest
import sqlalchemy.ext.asyncio as sa_asyncio
from alembic.config import Config
from alembic.runtime.environment import EnvironmentContext
from alembic.script import ScriptDirectory
from sqlalchemy import event
from sqlalchemy.engine.interfaces import Dialect
from sqlalchemy.ext.asyncio import AsyncEngine
from sqlalchemy.pool import ConnectionPoolEntry

REPO_ROOT = Path(__file__).resolve().parent.parent

# Port 1 is never connected to: the listener below raises first. The URL only
# has to parse and name the asyncpg dialect.
PROBE_URL = "postgresql+asyncpg://probe:probe@127.0.0.1:1/probe"


class _NoConnect(Exception):
    """Raised from a `do_connect` listener to read env.py's driver parameters
    without opening a socket."""


@dataclass
class _EnvEngine:
    """Three readings of the one engine `migrations/env.py` builds."""

    kwargs: dict[str, Any] = field(default_factory=dict)
    """Keywords env.py passed to `async_engine_from_config` itself."""

    from_url: dict[str, Any] = field(default_factory=dict)
    """What the URL alone yields, before any `connect_args` merge."""

    cparams: dict[str, Any] = field(default_factory=dict)
    """What asyncpg is about to be called with, after the merge."""


def _run_env_py(monkeypatch: pytest.MonkeyPatch) -> _EnvEngine:
    """Exec `migrations/env.py` and return what its engine would connect with."""
    captured = _EnvEngine()
    real = sa_asyncio.async_engine_from_config

    def spy(
        configuration: dict[str, Any], prefix: str = "sqlalchemy.", **kwargs: Any
    ) -> AsyncEngine:
        captured.kwargs.update(kwargs)
        engine = real(configuration, prefix=prefix, **kwargs)
        captured.from_url.update(engine.dialect.create_connect_args(engine.url)[1])

        @event.listens_for(engine.sync_engine, "do_connect")
        def _capture(
            dialect: Dialect,
            conn_rec: ConnectionPoolEntry,
            cargs: tuple[Any, ...],
            cparams: dict[str, Any],
        ) -> None:
            captured.cparams.update(cparams)
            raise _NoConnect

        return engine

    # env.py binds this name at exec time, so patching the package attribute
    # before `run_env()` is what it resolves.
    monkeypatch.setattr(sa_asyncio, "async_engine_from_config", spy)
    # `tests/conftest.py::pg_url` exports this for the whole session, pointing
    # at the testcontainers Postgres. Removed so the URL under test is this
    # file's, whether or not that fixture has run.
    monkeypatch.delenv("POSTERN_DATABASE_URL", raising=False)

    config = Config()
    config.set_main_option("script_location", str(REPO_ROOT / "migrations"))
    config.set_main_option("sqlalchemy.url", PROBE_URL)
    script = ScriptDirectory.from_config(config)

    with pytest.raises(_NoConnect), EnvironmentContext(config, script, fn=lambda rev, ctx: []):
        script.run_env()
    return captured


def test_migrations_build_an_engine_with_no_deadlines(monkeypatch: pytest.MonkeyPatch) -> None:
    captured = _run_env_py(monkeypatch)

    assert "connect_args" not in captured.kwargs, (
        "migrations/env.py now passes connect_args; a command_timeout there kills a "
        f"long migration mid-statement: {captured.kwargs}"
    )
    # Non-empty, so the set difference below is a real comparison rather than
    # two empty dicts agreeing.
    assert captured.from_url, "do_connect never fired with the URL's own parameters"
    assert set(captured.cparams) - set(captured.from_url) == set(), (
        "migrations/env.py added driver parameters the URL did not: "
        f"{set(captured.cparams) - set(captured.from_url)}"
    )
    # Named individually because these two are exactly what `Database` sets
    # and what a copy-across would bring with it.
    assert "command_timeout" not in captured.cparams
    assert "timeout" not in captured.cparams

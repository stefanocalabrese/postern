"""A failed migration prints no statement, bound value or DETAIL (migrations/env.py).

`alembic upgrade head` is the one process here that is not a service, so no
record factory of an app factory is in it, and an uncaught failure reaches the
terminal as the interpreter's traceback, which does not go through `logging`:
the exception chain's text, `[SQL: ...]` and a constraint violation's `DETAIL:
Key (a)=(value) already exists`. `hide_parameters=True` removes bound
parameters only.

Two things in `migrations/env.py` answer it, each tested here the way an
operator meets it, in a real `python -m alembic upgrade head` against a real
Postgres:

* `install_sql_safe_logging()` runs AFTER `fileConfig`, so a record a migration
  logs about a driver error it caught is sanitised on its way to the console
  handler `alembic.ini` configures;
* a driver error that escapes the run is replaced by a fixed
  `RuntimeError("migration failed: <type and SQLSTATE>...") from None`. The
  operator keeps what they need (the type, the SQLSTATE, the INFO line naming
  the revision that was running) and is told the rest is in Postgres' own log.
  Any other exception, a plain `ValueError` in a revision for one, passes
  through untouched.

The revisions live in a temporary directory and run against a database created
for the test, never the suite's. The sentinel is built from two halves so that
no source line a traceback could print contains it.
"""

import asyncio
import os
import subprocess
import sys
import textwrap
from collections.abc import Iterator
from pathlib import Path

import asyncpg  # type: ignore[import-untyped]
import pytest

ROOT = Path(__file__).resolve().parent.parent
SENTINEL = "bf_mig_leak_" + "7731"

_REVISION_HEADER = """
import logging

import sqlalchemy as sa
from alembic import op

HALF = "bf_mig_leak_"
SENTINEL = HALF + "7731"

revision = "bfmig0001"
down_revision = None
branch_labels = None
depends_on = None
"""

REVISIONS: dict[str, str] = {
    # The failing statement itself carries the value, and so does the DETAIL.
    "unique violation": _REVISION_HEADER
    + textwrap.dedent(
        """
        def upgrade():
            op.execute("CREATE TABLE bf_dup (a text UNIQUE)")
            op.execute(f"INSERT INTO bf_dup VALUES ('{SENTINEL}')")
            op.execute(f"INSERT INTO bf_dup VALUES ('{SENTINEL}')")
        """
    ),
    # A bound parameter, as an application statement would carry it.
    "bound parameter": _REVISION_HEADER
    + textwrap.dedent(
        """
        def upgrade():
            op.get_bind().execute(sa.text("SELECT CAST(:p AS int)"), {"p": SENTINEL})
        """
    ),
    # Not a driver error: must pass through untouched.
    "plain error": _REVISION_HEADER
    + textwrap.dedent(
        """
        def upgrade():
            raise ValueError("plain detail of a revision bug")
        """
    ),
    # Succeeds, but logs a driver error it caught, through the ini's console handler.
    "caught and logged": _REVISION_HEADER
    + textwrap.dedent(
        """
        def upgrade():
            bind = op.get_bind()
            try:
                with bind.begin_nested():
                    bind.execute(sa.text("SELECT CAST(:p AS int)"), {"p": SENTINEL})
            except Exception as caught:
                logging.getLogger("alembic.bf_probe").error("caught: %s", caught)
                logging.getLogger("alembic.bf_probe").error("in a list: %s", [[caught]])
        """
    ),
}


def _plain_url(url: str) -> str:
    return url.replace("postgresql+asyncpg://", "postgresql://", 1)


@pytest.fixture
def fresh_database(pg_url: str) -> Iterator[str]:
    """An empty database in the suite's container, dropped afterwards."""
    name = f"bf_mig_{os.getpid()}"

    async def run(sql: str) -> None:
        connection = await asyncpg.connect(_plain_url(pg_url))
        try:
            await connection.execute(sql)
        finally:
            await connection.close()

    asyncio.run(run(f"DROP DATABASE IF EXISTS {name}"))
    asyncio.run(run(f"CREATE DATABASE {name}"))
    yield pg_url.rsplit("/", 1)[0] + "/" + name
    asyncio.run(run(f"DROP DATABASE IF EXISTS {name} WITH (FORCE)"))


def _alembic_upgrade(
    url: str, revision_source: str, tmp_path: Path
) -> subprocess.CompletedProcess[str]:
    versions = tmp_path / "versions"
    versions.mkdir()
    (versions / "bfmig0001_probe.py").write_text(revision_source)
    ini = tmp_path / "alembic.ini"
    template = (ROOT / "alembic.ini").read_text()
    lines = []
    for line in template.splitlines():
        if line.startswith("script_location"):
            line = f"script_location = {ROOT / 'migrations'}"
        lines.append(line)
    lines.insert(lines.index("[alembic]") + 1, f"version_locations = {versions}")
    ini.write_text("\n".join(lines) + "\n")
    env = {k: v for k, v in os.environ.items() if not k.startswith("POSTERN_")}
    env["POSTERN_DATABASE_URL"] = url
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    return subprocess.run(  # noqa: S603 - fixed argv, no shell, this repo's own alembic
        [sys.executable, "-m", "alembic", "-c", str(ini), "upgrade", "head"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        env=env,
        timeout=120,
    )


@pytest.mark.parametrize("name", ["unique violation", "bound parameter"])
def test_a_failed_migration_prints_no_statement_value_or_detail(
    name: str, fresh_database: str, tmp_path: Path
) -> None:
    result = _alembic_upgrade(fresh_database, REVISIONS[name], tmp_path)
    everything = result.stdout + result.stderr
    assert result.returncode != 0, everything
    assert SENTINEL not in everything, everything
    assert "RuntimeError: migration failed:" in result.stderr, result.stderr
    assert "sqlalchemy.exc." in result.stderr
    assert "sqlstate=" in result.stderr or "client-side" in result.stderr
    assert "Postgres" in result.stderr  # where to read the rest
    assert "Running upgrade" in result.stderr  # the revision that was running


def test_a_unique_violation_names_its_sqlstate(fresh_database: str, tmp_path: Path) -> None:
    result = _alembic_upgrade(fresh_database, REVISIONS["unique violation"], tmp_path)
    assert "23505" in result.stderr, result.stderr
    assert "IntegrityError" in result.stderr


def test_the_original_exception_is_not_printed_as_a_cause(
    fresh_database: str, tmp_path: Path
) -> None:
    result = _alembic_upgrade(fresh_database, REVISIONS["unique violation"], tmp_path)
    assert "The above exception was the direct cause" not in result.stderr
    assert "During handling of the above exception" not in result.stderr
    assert "[SQL:" not in result.stderr and "DETAIL" not in result.stderr


def test_an_error_that_is_not_a_driver_error_passes_through_untouched(
    fresh_database: str, tmp_path: Path
) -> None:
    result = _alembic_upgrade(fresh_database, REVISIONS["plain error"], tmp_path)
    assert result.returncode != 0
    assert "ValueError: plain detail of a revision bug" in result.stderr
    assert "migration failed" not in result.stderr


def test_a_record_a_migration_logs_about_a_caught_driver_error_is_sanitised(
    fresh_database: str, tmp_path: Path
) -> None:
    """The factory is installed after `fileConfig`, so it is on the ini's console handler."""
    result = _alembic_upgrade(fresh_database, REVISIONS["caught and logged"], tmp_path)
    everything = result.stdout + result.stderr
    assert result.returncode == 0, everything
    assert "caught:" in result.stderr and "in a list:" in result.stderr
    assert SENTINEL not in everything, everything
    assert "sqlalchemy.exc." in result.stderr

import asyncio
import os
from collections.abc import Callable
from logging.config import fileConfig

import postern_core.store.models  # noqa: F401  registers the tables on the metadata
from alembic import context
from postern_core.env_inventory import enforce_known_environment
from postern_core.log_safety import (
    chain_holds_driver_error,
    describe_exception,
    install_sql_safe_logging,
)
from postern_core.store.base import Base
from sqlalchemy import pool
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import async_engine_from_config

# this is the Alembic Config object, which provides
# access to the values within the .ini file in use.
config = context.config

# BEFORE THE READ BELOW, because the read below is the one with the silent
# failure. A migration is the worst place in this repository for a misspelt
# variable name: `POSTERN_DATABASE_UR` leaves the override untaken, and
# `alembic upgrade` then runs against whatever `alembic.ini`'s `sqlalchemy.url`
# names. In this repository that is the generated placeholder
# `driver://user:pass@localhost/dbname`, so the failure is loud by accident; an
# operator who puts a real URL there -- which is the ordinary way to use
# alembic -- has a migration applying DDL to the wrong database and no
# indication that it did.
#
# `enforce_known_environment` refuses on any `POSTERN_` name no code reads, so
# the typo is caught here rather than diagnosed afterwards from a schema. The
# service it claims is `migrations`, which reads exactly three variables:
# `POSTERN_DATABASE_URL` and the guard's own two lists. That set is narrow
# because this process imports only `postern_core.store`, which reads no
# environment variable at all, which
# `tests/test_settings_bounds.py::TestEveryEnvironmentReadNamesAnInventoriedVariable`
# derives from the syntax tree rather than trusting this sentence.
#
# WHEN IT REFUSES, `alembic upgrade` exits non-zero and the deploy stops before
# the migration runs. That is the correct direction and worth saying plainly: a
# migration that would have altered the wrong schema does not run, and a
# deployment that cannot migrate does not roll out behind it.
enforce_known_environment(service="migrations")

# `POSTERN_DATABASE_URL` overrides `alembic.ini`'s `sqlalchemy.url` when set,
# which is how CI's Postgres service container and the drift-check target in
# the Makefile point this at a database without editing the ini file.
if (url := os.environ.get("POSTERN_DATABASE_URL")) is not None:
    config.set_main_option("sqlalchemy.url", url)

# Interpret the config file for Python logging.
# This line sets up loggers basically.
#
# The generated guard here only checks `is not None`, but
# `config.config_file_name` is the literal string "alembic.ini" even when no
# such file exists (e.g. a future pyproject.toml-only configuration), so that
# guard alone crashes with `FileNotFoundError: alembic.ini doesn't exist`.
# This repo does keep an `alembic.ini` today, so the extra `os.path.exists`
# check changes nothing right now -- it costs nothing and removes a landmine
# for whoever later moves the config into `pyproject.toml`.
# `disable_existing_loggers` defaults to `True`, which sets `.disabled` on
# every logger that already exists in this process, for the rest of the
# process's life. Harmless when migrations run in their own process; not
# harmless when `alembic upgrade head` runs in-process at application
# startup, which silences every logger the application created before this
# line, including ones about to report that a downstream store is unreachable.
if config.config_file_name is not None and os.path.exists(config.config_file_name):
    fileConfig(config.config_file_name, disable_existing_loggers=False)

# After `fileConfig`, so everything it configures is already in place. The
# record factory is process-global and `fileConfig` replaces handlers, not the
# factory. This process is not a service, so no app factory installed it:
# without this call a record a migration logs about a driver error reaches the
# console handler raw. It also routes `warnings.warn` through logging, with a
# SQLAlchemy warning's text withheld.
install_sql_safe_logging()


def _fail_without_the_driver_text(run: Callable[[], None]) -> None:
    """Run ``run``; a driver error that escapes it is replaced by a fixed error.

    An uncaught failure is printed by the interpreter, not by `logging`, so the
    factory above never sees it: the traceback would carry the exception chain's
    text, `[SQL: ...]` (a migration's literal values included) and a constraint
    violation's `DETAIL: Key (a)=(value) already exists`. What the operator needs
    to act is the type, the SQLSTATE and which revision was running, and they
    have all three: `describe_exception` and the `Running upgrade X -> Y` line
    alembic logs at INFO before it runs. The rest is in Postgres' own log.

    The replacement is raised OUTSIDE the `except` block, so the original is
    neither the `__cause__` nor the `__context__` of what propagates and no
    traceback frame of it is printed. Anything that is not a driver error is
    re-raised as it came, so a bug in a revision keeps its message.
    """
    failure: str | None = None
    try:
        run()
    except Exception as exc:
        if not chain_holds_driver_error(exc):
            raise
        failure = describe_exception(exc)
    if failure is not None:
        raise RuntimeError(
            f"migration failed: {failure}. The statement, its parameters and the "
            "driver's message are withheld from this output; read the database's "
            "own log for them (treat it as customer data). The last "
            "'Running upgrade' line above names the revision that was running."
        )

# add your model's MetaData object here
# for 'autogenerate' support
# from myapp import mymodel
# target_metadata = mymodel.Base.metadata
target_metadata = Base.metadata

# other values from the config, defined by the needs of env.py,
# can be acquired:
# my_important_option = config.get_main_option("my_important_option")
# ... etc.


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode.

    This configures the context with just a URL
    and not an Engine, though an Engine is acceptable
    here as well.  By skipping the Engine creation
    we don't even need a DBAPI to be available.

    Calls to context.execute() here emit the given string to the
    script output.

    """
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        _fail_without_the_driver_text(context.run_migrations)


def do_run_migrations(connection: Connection) -> None:
    # Without `compare_server_default`, `alembic check` only compares column
    # presence, type and nullability -- a `server_default` edited on just the
    # model or just the migration passes silently. This is the online path
    # `alembic check` runs, so it is the one that needs the flag.
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        compare_server_default=True,
    )

    with context.begin_transaction():
        context.run_migrations()


async def run_async_migrations() -> None:
    """In this scenario we need to create an Engine
    and associate a connection with the context.

    """

    connectable = async_engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
        # A failed migration statement's error text then carries no bound
        # values, as for the two services' engines.
        hide_parameters=True,
    )

    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)

    await connectable.dispose()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode."""

    _fail_without_the_driver_text(lambda: asyncio.run(run_async_migrations()))


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()

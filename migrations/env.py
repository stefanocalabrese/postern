import asyncio
import os
from logging.config import fileConfig

import postern_core.store.models  # noqa: F401  registers the tables on the metadata
from alembic import context
from postern_core.store.base import Base
from sqlalchemy import pool
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import async_engine_from_config

# this is the Alembic Config object, which provides
# access to the values within the .ini file in use.
config = context.config

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
        context.run_migrations()


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
    )

    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)

    await connectable.dispose()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode."""

    asyncio.run(run_async_migrations())


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()

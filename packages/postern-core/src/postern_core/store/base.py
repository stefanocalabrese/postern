"""Declarative base for every Postern table.

Kept separate from `models` so Alembic's `env.py` can import the metadata
without importing the models twice under different module paths.
"""

from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    """Base class for all ORM models."""

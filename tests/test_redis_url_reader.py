"""``POSTERN_REDIS_URL`` is read in one place, and a blank value is unset everywhere.

``postern_core.config.redis_url_from_env`` strips and returns ``None`` for a
blank value, the convention that module's header states for every variable.
Until it existed the variable was read in eight places with three behaviours:
``" "`` was truthy at the store factories, which then built a Redis store with
a one-space URL, and falsy only where someone had added ``.strip()``. The
table below drives every call site with the same blank values.
"""

from __future__ import annotations

import io
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from postern_core.auth.device_codes import create_device_code_store
from postern_core.auth.refresh_sessions import create_refresh_session_store
from postern_core.auth.revocation import create_revocation_store
from postern_core.auth.revoke_cli import main as revoke_main
from postern_core.config import redis_url_from_env
from postern_core.risk.session import create_session_store

from services.confirm.customer_rate_limit import create_customer_rate_limit_store

BLANKS = ["", " ", " \t\n"]

FACTORIES: list[Callable[[], Any]] = [
    create_device_code_store,
    create_refresh_session_store,
    create_revocation_store,
    create_session_store,
    create_customer_rate_limit_store,
]


@pytest.fixture(autouse=True)
def _no_redis(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("POSTERN_REDIS_URL", raising=False)


class TestTheReader:
    def test_unset_is_none(self) -> None:
        assert redis_url_from_env() is None

    @pytest.mark.parametrize("blank", BLANKS)
    def test_blank_is_none(self, monkeypatch: pytest.MonkeyPatch, blank: str) -> None:
        monkeypatch.setenv("POSTERN_REDIS_URL", blank)
        assert redis_url_from_env() is None

    def test_a_value_is_returned_stripped(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("POSTERN_REDIS_URL", "  redis://cache:6379/1 \n")
        assert redis_url_from_env() == "redis://cache:6379/1"


class TestEveryCallSiteAgrees:
    @pytest.mark.parametrize("blank", BLANKS)
    @pytest.mark.parametrize("factory", FACTORIES, ids=lambda f: f.__name__)
    def test_a_blank_url_selects_the_in_memory_backend(
        self, monkeypatch: pytest.MonkeyPatch, factory: Callable[[], Any], blank: str
    ) -> None:
        monkeypatch.setenv("POSTERN_REDIS_URL", blank)
        assert type(factory()).__name__.startswith("InMemory")

    @pytest.mark.parametrize("factory", FACTORIES, ids=lambda f: f.__name__)
    def test_a_url_selects_redis(
        self, monkeypatch: pytest.MonkeyPatch, factory: Callable[[], Any]
    ) -> None:
        monkeypatch.setenv("POSTERN_REDIS_URL", " redis://127.0.0.1:6379/0 ")
        assert type(factory()).__name__.startswith("Redis")

    @pytest.mark.parametrize("blank", BLANKS)
    def test_the_revoke_cli_refuses_a_blank_url(
        self, monkeypatch: pytest.MonkeyPatch, blank: str
    ) -> None:
        monkeypatch.setenv("POSTERN_REDIS_URL", blank)
        err = io.StringIO()
        assert revoke_main(["list"], out=io.StringIO(), err=err) == 1
        assert "POSTERN_REDIS_URL is not set" in err.getvalue()


def test_no_module_reads_the_variable_except_the_one_reader() -> None:
    """A raw read in a module under ``packages`` or ``services`` is the drift."""
    root = Path(__file__).resolve().parent.parent
    allowed = {root / "packages/postern-core/src/postern_core/config.py"}
    needles = ('environ.get("POSTERN_REDIS_URL"', 'getenv("POSTERN_REDIS_URL"')
    offenders = [
        str(path.relative_to(root))
        for base in ("packages", "services")
        for path in (root / base).rglob("*.py")
        if path not in allowed and any(n in path.read_text() for n in needles)
    ]
    assert offenders == []

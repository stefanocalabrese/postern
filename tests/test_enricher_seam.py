"""The pairing network enricher seam: what is found, and what refuses to start.

Section 3 of ``dev-docs/pairing-network-signal-spec.md``. The distributions
here are REAL, in the sense ``tests/test_module_seam.py`` means it: a
``.dist-info`` directory with an ``entry_points.txt`` beside a module on a
temporary ``sys.path`` entry, which is what ``importlib.metadata`` reads.
Nothing under ``services/`` and nothing in either ``pyproject.toml`` is
touched to make one register.
"""

from __future__ import annotations

import asyncio
import importlib
import sys
import textwrap
from collections.abc import Iterator
from pathlib import Path

import pytest
from fastmcp.server.auth.providers.jwt import JWTVerifier, RSAKeyPair
from postern_core.auth.device_keys import no_enrolled_devices
from postern_core.modules.enrichers import (
    ENRICHER_GROUP,
    EnricherSeamViolation,
    load_network_enricher,
)
from postern_core.risk.pairing_network import NetworkFacts
from starlette.applications import Starlette

from services.confirm.device_auth import PAIRING_ENRICHMENT_SLOTS
from services.confirm.main import create_confirm_app
from services.confirm.settings import ConfirmSettings

ASYNC_SOURCE = """
    from postern_core.risk.pairing_network import NetworkFacts

    class Enricher:
        async def lookup(self, ip: str) -> NetworkFacts | None:
            return NetworkFacts(asn=64500, country="ES")

    ENRICHER = Enricher()
"""

SYNC_SOURCE = """
    class Enricher:
        def lookup(self, ip):
            return None

    ENRICHER = Enricher()
"""

CLASS_SOURCE = """
    class Enricher:
        async def lookup(self, ip):
            return None

    ENRICHER = Enricher
"""

NO_LOOKUP_SOURCE = """
    ENRICHER = object()
"""

BROKEN_SOURCE = """
    raise ImportError("this provider's data file is missing")
"""


def _write_distribution(root: Path, *, dist_name: str, module_name: str, source: str) -> None:
    """One importable module and the ``.dist-info`` declaring it in ``ENRICHER_GROUP``."""
    (root / f"{module_name}.py").write_text(textwrap.dedent(source))
    info = root / f"{dist_name.replace('-', '_')}-0.0.0.dist-info"
    info.mkdir()
    (info / "METADATA").write_text(f"Metadata-Version: 2.1\nName: {dist_name}\nVersion: 0.0.0\n")
    (info / "entry_points.txt").write_text(
        f"[{ENRICHER_GROUP}]\n{module_name} = {module_name}:ENRICHER\n"
    )


@pytest.fixture
def installed(tmp_path: Path) -> Iterator[Path]:
    """A temporary ``sys.path`` entry, with the metadata caches invalidated on
    both edges for the reason ``tests/test_module_seam.py``'s fixture gives."""
    sys.path.insert(0, str(tmp_path))
    importlib.invalidate_caches()
    try:
        yield tmp_path
    finally:
        sys.path.remove(str(tmp_path))
        importlib.invalidate_caches()
        for name in [n for n in sys.modules if n.startswith("fixture_enricher_")]:
            del sys.modules[name]


def _app(**kwargs: object) -> Starlette:
    key_pair = RSAKeyPair.generate()
    verifier = JWTVerifier(
        public_key=key_pair.public_key, issuer="https://app.test.invalid", audience="x"
    )
    return create_confirm_app(
        ConfirmSettings.for_testing(),
        assertion_verifier=verifier,
        device_key_store=no_enrolled_devices(),
        **kwargs,  # type: ignore[arg-type]
    )


# ---------------------------------------------------------------------------
# The loader.
# ---------------------------------------------------------------------------


def test_the_shipped_tree_installs_no_enricher() -> None:
    assert load_network_enricher() is None


def test_one_installed_enricher_is_the_one_returned(installed: Path) -> None:
    _write_distribution(
        installed, dist_name="geo-one", module_name="fixture_enricher_one", source=ASYNC_SOURCE
    )

    enricher = load_network_enricher()

    assert enricher is not None
    assert type(enricher).__name__ == "Enricher"
    assert asyncio.run(enricher.lookup("192.0.2.1")) == NetworkFacts(asn=64500, country="ES")


def test_two_installed_enrichers_refuse_naming_both(installed: Path) -> None:
    _write_distribution(
        installed, dist_name="geo-one", module_name="fixture_enricher_one", source=ASYNC_SOURCE
    )
    _write_distribution(
        installed, dist_name="geo-two", module_name="fixture_enricher_two", source=ASYNC_SOURCE
    )

    with pytest.raises(EnricherSeamViolation) as refused:
        load_network_enricher()

    assert "fixture_enricher_one" in str(refused.value)
    assert "fixture_enricher_two" in str(refused.value)


def test_an_enricher_that_will_not_import_refuses(installed: Path) -> None:
    _write_distribution(
        installed,
        dist_name="geo-broken",
        module_name="fixture_enricher_broken",
        source=BROKEN_SOURCE,
    )

    with pytest.raises(EnricherSeamViolation, match="could not be imported"):
        load_network_enricher()


def test_a_synchronous_lookup_refuses(installed: Path) -> None:
    _write_distribution(
        installed, dist_name="geo-sync", module_name="fixture_enricher_sync", source=SYNC_SOURCE
    )

    with pytest.raises(EnricherSeamViolation, match="not an async method"):
        load_network_enricher()


def test_an_object_with_no_lookup_refuses(installed: Path) -> None:
    _write_distribution(
        installed,
        dist_name="geo-none",
        module_name="fixture_enricher_none",
        source=NO_LOOKUP_SOURCE,
    )

    with pytest.raises(EnricherSeamViolation, match="not an async method"):
        load_network_enricher()


def test_an_entry_point_naming_a_class_refuses(installed: Path) -> None:
    """The value resolves to an instance, as a module's resolves to its ``MODULE``."""
    _write_distribution(
        installed, dist_name="geo-class", module_name="fixture_enricher_class", source=CLASS_SOURCE
    )

    with pytest.raises(EnricherSeamViolation, match="must resolve to an instance"):
        load_network_enricher()


# ---------------------------------------------------------------------------
# Composition.
# ---------------------------------------------------------------------------


def test_the_app_holds_no_enricher_when_none_is_installed() -> None:
    app = _app()
    assert app.state.pairing_network_enricher is None


def test_the_app_holds_the_installed_enricher(installed: Path) -> None:
    _write_distribution(
        installed, dist_name="geo-one", module_name="fixture_enricher_one", source=ASYNC_SOURCE
    )
    app = _app()
    assert type(app.state.pairing_network_enricher).__name__ == "Enricher"


def test_an_explicit_none_wins_over_an_installed_enricher(installed: Path) -> None:
    _write_distribution(
        installed, dist_name="geo-one", module_name="fixture_enricher_one", source=ASYNC_SOURCE
    )
    app = _app(network_enricher=None)
    assert app.state.pairing_network_enricher is None


def test_a_supplied_enricher_is_used_as_given() -> None:
    class Supplied:
        async def lookup(self, ip: str) -> NetworkFacts | None:
            return None

    supplied = Supplied()
    app = _app(network_enricher=supplied)
    assert app.state.pairing_network_enricher is supplied


def test_the_app_holds_one_semaphore_of_eight_slots() -> None:
    app = _app()
    slots = app.state.pairing_network_slots
    assert isinstance(slots, asyncio.Semaphore)
    assert PAIRING_ENRICHMENT_SLOTS == 8
    assert slots._value == 8


@pytest.mark.parametrize(
    ("source", "match"),
    [
        (BROKEN_SOURCE, "could not be imported"),
        (SYNC_SOURCE, "not an async method"),
        (NO_LOOKUP_SOURCE, "not an async method"),
        (CLASS_SOURCE, "must resolve to an instance"),
    ],
    ids=["broken", "sync", "no-lookup", "class"],
)
def test_each_refusal_lands_at_composition(installed: Path, source: str, match: str) -> None:
    _write_distribution(
        installed, dist_name="geo-bad", module_name="fixture_enricher_bad", source=source
    )

    with pytest.raises(EnricherSeamViolation, match=match):
        _app()


def test_two_enrichers_refuse_at_composition(installed: Path) -> None:
    _write_distribution(
        installed, dist_name="geo-one", module_name="fixture_enricher_one", source=ASYNC_SOURCE
    )
    _write_distribution(
        installed, dist_name="geo-two", module_name="fixture_enricher_two", source=ASYNC_SOURCE
    )

    with pytest.raises(EnricherSeamViolation, match="at most one may be"):
        _app()

"""How the confirm service finds the one installed pairing network enricher, if any.

An enricher answers "which autonomous system and which country is this
address in" for ``POST /scan``'s creator-versus-scanner comparison
(``postern_core.risk.pairing_network``). None ships here. An operator who
wants one installs a distribution declaring an entry point:

    [project.entry-points."postern.pairing_network_enrichers"]
    geo = "operator_geo:ENRICHER"      # an instance with ``async def lookup``

The value resolves to an INSTANCE, the way a module's entry point resolves to
its ``MODULE`` rather than to a class, and it is found by the mechanism
decision 0018 chose for modules: ``importlib.metadata`` at composition, out
of what the image installs.

WHAT THE LOADER REFUSES, each at composition and never at a request:

- More than one installed. Two providers disagreeing about one address have
  no correct resolution, and choosing by installation order is the failure
  decision 0018 refuses for write routing.
- An entry point that will not import.
- One that resolves to a class, or to an object whose ``lookup`` is not a
  coroutine function. A ``runtime_checkable`` Protocol check is not enough:
  it tests that the attribute exists, not that it is async, and a
  synchronous ``lookup`` would block the event loop every scan runs on.

TRUST. An enricher runs inside ``services/confirm``, which holds the write
signing key, and it is handed every creator and scanner address. This
package's ``__init__`` docstring on what a module can do applies without
softening: installing one is as consequential as merging a commit into this
repository.

THE GROUP NAME IS NOT IN ``postern_core.modules.groups``. That module exists
to keep the write group's name reachable from the read path without the write
half's types, and no such constraint applies to this group.
"""

from __future__ import annotations

import inspect
from importlib.metadata import EntryPoint, entry_points
from typing import cast

from postern_core.risk.pairing_network import NetworkEnricher

__all__ = [
    "ENRICHER_GROUP",
    "EnricherSeamViolation",
    "load_network_enricher",
]

#: Where an operator's distribution declares its enricher. The value resolves
#: to an instance satisfying ``postern_core.risk.pairing_network.NetworkEnricher``.
ENRICHER_GROUP = "postern.pairing_network_enrichers"


class EnricherSeamViolation(RuntimeError):
    """An installed enricher set the confirm service refuses to start with.

    Raised during composition, never during a request: every condition it
    covers is a property of what is installed.
    """


def _named(point: EntryPoint) -> str:
    return f"{point.name!r} = {point.value!r}"


def load_network_enricher() -> NetworkEnricher | None:
    """The one installed enricher, ``None`` when none is, or refuse to start.

    Raises:
        EnricherSeamViolation: for more than one entry point in
            ``ENRICHER_GROUP``, naming every one; for one that will not import;
            and for one that resolves to a class or to an object whose
            ``lookup`` is not a coroutine function.
    """
    points = sorted(entry_points(group=ENRICHER_GROUP), key=lambda p: (p.name, p.value))
    if not points:
        return None
    if len(points) > 1:
        raise EnricherSeamViolation(
            f"{len(points)} pairing network enrichers are installed "
            f"({', '.join(_named(p) for p in points)}); at most one may be. Two "
            "providers disagreeing about one address have no correct resolution, "
            "and choosing by installation order would make the recorded match "
            "depend on how the image was built."
        )
    point = points[0]
    try:
        loaded = point.load()
    except Exception as exc:  # noqa: BLE001 -- re-raised, with the entry point named
        raise EnricherSeamViolation(
            f"pairing network enricher entry point {_named(point)} could not be "
            f"imported: {type(exc).__name__}: {exc}"
        ) from exc
    if isinstance(loaded, type):
        raise EnricherSeamViolation(
            f"pairing network enricher entry point {_named(point)} resolved to the "
            f"class {loaded.__name__}; it must resolve to an instance"
        )
    lookup = getattr(loaded, "lookup", None)
    if lookup is None or not inspect.iscoroutinefunction(lookup):
        raise EnricherSeamViolation(
            f"pairing network enricher entry point {_named(point)} resolved to "
            f"{type(loaded).__name__}, whose lookup is not an async method. A "
            "synchronous lookup would block every request on the replica while "
            "it ran, and the time budget around it could not stop that."
        )
    return cast(NetworkEnricher, loaded)

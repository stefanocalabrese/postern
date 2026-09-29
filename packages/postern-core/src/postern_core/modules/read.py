"""The read half of a module: what it declares, and how the host finds it.

A module's read half is a `ReadModule` holding `ReadTool`s. Each tool carries
its MCP name, its consent domain, the two annotation hints, and a `build`
callable that turns a `ReadContext` into the handler. The host does the FastMCP
registration, which is deliberate: `@mcp.tool`'s signature, `ToolAnnotations`'
import path and the `auth=` parameter are all framework facts CLAUDE.md records
as version traps, and a module that never touches them survives a FastMCP major
without an edit.

WHY `build` IS A CALLABLE AND NOT A METHOD ON A HANDLER CLASS. The handler
needs the customer resolver and the backend reader, both of which exist only
once the composition root has assembled them, and neither of which a module may
hold a second copy of -- `services/api/main.py` says why there is exactly one
resolver object. A factory taking a `ReadContext` is the smallest shape that
delivers both at registration time and lets the handler stay a plain async
function whose signature and docstring FastMCP reads to build the tool schema.

WHAT THE LOADER REFUSES, each for a reason an operator would otherwise find out
from a served request rather than from a failed start:

- A distribution declaring both entry-point groups
  (`refuse_distributions_declaring_both_halves`). One wheel carrying both
  halves defeats the image split, because ``site-packages`` is copied whole.
- Two modules declaring the same tool name (`refuse_duplicate_tool_names`).
  Last-wins would make the tool surface depend on installation order, which is
  the one thing ``tool-surface.json`` cannot pin.
- An entry point resolving to something that is not a `ReadModule`.
- A read module whose import pulled `postern_core.modules.write` into the
  process (`_refuse_write_half_in_the_read_path`). That is the smuggling route
  `.importlinter` cannot see, because a third-party module is not in its graph.

WHAT IT CANNOT REFUSE, said here rather than left to be discovered: anything a
module does after it is loaded. See this package's ``__init__`` docstring --
there is no sandbox, and the four refusals above are structural checks on
DECLARATIONS, not a security boundary around behaviour.
"""

from __future__ import annotations

import dataclasses
import re
import sys
from collections.abc import Awaitable, Callable, Iterable, Sequence
from importlib.metadata import EntryPoint, entry_points
from typing import Any

from postern_core.facade.protocol import BackendReader
from postern_core.identity import CustomerResolver
from postern_core.modules.groups import READ_GROUP, WRITE_GROUP

__all__ = [
    "READ_GROUP",
    "WRITE_GROUP",
    "ModuleSeamViolation",
    "ReadContext",
    "ReadModule",
    "ReadTool",
    "ToolHandler",
    "load_read_modules",
    "refuse_distributions_declaring_both_halves",
    "refuse_duplicate_tool_names",
]

#: The module whose presence in `sys.modules` means a write half was imported.
#:
#: Named as a string rather than imported, which is the whole point: importing
#: it here would make the read path's own loader the first violation.
_WRITE_PROTOCOL = "postern_core.modules.write"

#: An MCP tool name: lowercase, one optional dot, no spaces.
#:
#: One dot at most, because the shipped surface is ``<domain>.<verb>`` and
#: `start_session` -- the one tool with no domain, for the reason
#: `services/api/tools/bootstrap.py` gives. A name outside this shape is
#: refused at declaration: FastMCP accepts it, `tool-surface.json` records it,
#: and the operator finds out when a client cannot address it.
_TOOL_NAME_RE = re.compile(r"^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)?$")

#: What a module's `ReadTool.build` returns: the function FastMCP registers.
ToolHandler = Callable[..., Awaitable[Any]]


class ModuleSeamViolation(RuntimeError):
    """A module declaration the host refuses to serve.

    Raised during composition, never during a request: every condition it
    covers is a property of what is installed, so a process that starts is a
    process whose module set was accepted.
    """


@dataclasses.dataclass(frozen=True)
class ReadContext:
    """Everything a read tool handler is given, and nothing else.

    TWO FIELDS, AND WIDENING THIS IS A DECISION NOT A CONVENIENCE.
    `tests/test_module_seam.py::test_a_read_context_carries_only_the_resolver_and_the_backend`
    pins the set. A module that needed the `postern_core.store.engine.Database`,
    a key source or the token minter would be a module holding the credentials
    the key split exists to keep apart; a module that needs the customer and a
    way to read the backend is a module that can implement a read tool. The
    second is what this seam is for.

    This is not a security boundary -- see this package's ``__init__``
    docstring, a module can reach any of those objects by ordinary attribute
    access. It is the difference between a module that has to go looking and one
    that is handed the keys, which is the difference between a review finding
    something and a review having nothing to find.

    Attributes:
        resolver: Answers "which customer is this call for?". The SAME object
            the risk layer and the audit middleware read, so a budget charged
            and a row returned cannot disagree.
        backend: The read-only facade over the operator's backend. Carries the
            internal READ token minter, so it can reach read endpoints and no
            write endpoint has a key for it.
    """

    resolver: CustomerResolver
    backend: BackendReader


@dataclasses.dataclass(frozen=True)
class ReadTool:
    """One MCP tool a module registers on the read path.

    Attributes:
        name: The MCP tool name, e.g. ``cards.list``.
        consent_domain: The consent domain the host gates this tool on, or
            ``None`` for a tool reachable with no consent row. ``None`` is not
            a convenience: `services/api/consent.py` is what turns a domain
            into the Postgres-backed check, and a tool declaring ``None`` is
            asserting it discloses nothing a customer has to consent to.
        build: Given the `ReadContext`, return the handler. Called once, at
            registration.
        read_only: `mcp.types.ToolAnnotations`' ``read_only_hint``. Defaults
            true, and on the read path nothing else is accepted:
            `tests/test_no_write_from_api.py` asserts every registered tool is
            annotated read-only.
        open_world: ``open_world_hint``. Defaults false -- a banking read tool
            reaches the operator's own backend, not the open internet.
    """

    name: str
    consent_domain: str | None
    build: Callable[[ReadContext], ToolHandler]
    read_only: bool = True
    open_world: bool = False

    def __post_init__(self) -> None:
        if not _TOOL_NAME_RE.match(self.name):
            raise ValueError(
                f"{self.name!r} is not a usable tool name: a tool name is lowercase "
                "letters, digits and underscores, with at most one dot separating "
                "domain from verb (e.g. 'cards.list', or 'start_session')"
            )
        if self.consent_domain is not None and not self.consent_domain.isidentifier():
            raise ValueError(
                f"{self.consent_domain!r} is not a usable consent domain: it is a "
                "single identifier matching a row in the consent store, e.g. 'cards'"
            )

    def as_dict(self) -> dict[str, Any]:
        """The surface-file projection. Deliberately excludes `build`: the
        golden file records what a module DECLARES, and a function's identity
        is not reviewable in a diff."""
        return {
            "name": self.name,
            "consent_domain": self.consent_domain,
            "read_only": self.read_only,
            "open_world": self.open_world,
        }


@dataclasses.dataclass(frozen=True)
class ReadModule:
    """A module's read half: a name, and the tools it registers.

    Attributes:
        name: The module's own name, e.g. ``cards``. Appears in
            ``tool-surface.json`` beside each of its tools, so a diff says
            which module changed and not only which tool.
        tools: Its read tools. Empty is refused: an entry point that registers
            nothing is a packaging mistake that would otherwise be silent.
    """

    name: str
    tools: tuple[ReadTool, ...]

    def __post_init__(self) -> None:
        if not self.name.isidentifier():
            raise ValueError(f"{self.name!r} is not a usable module name: use an identifier")
        if not self.tools:
            raise ValueError(f"module {self.name!r} declares no tools")
        seen: set[str] = set()
        for tool in self.tools:
            if tool.name in seen:
                raise ValueError(f"module {self.name!r} declares {tool.name!r} twice")
            seen.add(tool.name)


def refuse_duplicate_tool_names(modules: Sequence[ReadModule]) -> None:
    """Refuse two modules declaring one tool name.

    Called on the discovered set by `load_read_modules`, and again on
    built-ins plus discovered by `services/api/server.py`'s `build_server`:
    the second call is the one that catches a module shadowing a shipped tool,
    which the first structurally cannot see.

    Raises:
        ModuleSeamViolation: naming the tool and both modules, because "tool
            already registered" without the two claimants is a message that
            sends an operator reading every module they have installed.
    """
    owner: dict[str, str] = {}
    for module in modules:
        for tool in module.tools:
            if tool.name in owner:
                raise ModuleSeamViolation(
                    f"tool {tool.name!r} is declared by both module {owner[tool.name]!r} "
                    f"and module {module.name!r}. Two modules cannot register one tool "
                    "name: which one answered would depend on installation order, and "
                    "the tool surface has to be the same on every replica of an image."
                )
            owner[tool.name] = module.name


def refuse_distributions_declaring_both_halves() -> None:
    """Refuse a distribution declaring both entry-point groups.

    THE RULE IS "ONE MODULE, TWO DISTRIBUTIONS" and this is the mechanical half
    of it. A wheel declaring `READ_GROUP` and `WRITE_GROUP` together cannot be
    installed on the read path without its write half, because a wheel installs
    as one unit into a ``site-packages`` both container images copy whole. The
    read image would then hold backend write routing -- audience, path, method,
    tier for every write operation the module defines -- whatever the Dockerfile
    copies and whatever `.importlinter` says about the in-repo tree.

    WHAT IT DOES NOT CLAIM. It does not stop the write half from being
    installed on the read path as a separate distribution, and it cannot: that
    is a deployment decision, enforced by what the image installs. It removes
    the case where the operator has no choice.

    Raises:
        ModuleSeamViolation: naming the distribution.
    """
    read_dists = _distributions_declaring(READ_GROUP)
    write_dists = _distributions_declaring(WRITE_GROUP)
    both = sorted(read_dists & write_dists)
    if both:
        raise ModuleSeamViolation(
            f"distribution {both[0]!r} declares both {READ_GROUP} and {WRITE_GROUP}. "
            "A module ships as two distributions, one per half, because "
            "site-packages is copied whole into both service images: a single "
            "distribution puts this module's backend write routing inside the read "
            f"container. Split it into {both[0]!r} and {both[0]}-write."
            + (f" Also affected: {both[1:]}." if len(both) > 1 else "")
        )


def _distributions_declaring(group: str) -> set[str]:
    """The distribution names declaring an entry point in ``group``.

    An entry point with no resolvable distribution is skipped rather than
    refused: `importlib.metadata.EntryPoint.dist` is ``None`` for one
    constructed by hand, which is a shape a test or an embedding host may
    legitimately produce, and refusing it would fail closed on something that
    cannot be the defect this function looks for -- a nameless distribution
    cannot be installed as one unit.
    """
    names: set[str] = set()
    for point in entry_points(group=group):
        dist = point.dist
        if dist is not None:
            names.add(dist.name)
    return names


def load_read_modules() -> tuple[ReadModule, ...]:
    """Every installed read module, in a fixed order, or refuse to start.

    Sorted by module name, not by entry-point discovery order, so
    ``tool-surface.json`` and a client's ``tools/list`` do not reorder
    themselves when a distribution is reinstalled.

    Raises:
        ModuleSeamViolation: for any of the four conditions in this module's
            docstring. Every one of them is a property of what is installed,
            so the failure belongs at composition and a process that starts has
            an accepted module set.
    """
    refuse_distributions_declaring_both_halves()
    write_half_was_already_here = _WRITE_PROTOCOL in sys.modules

    modules: list[ReadModule] = []
    for point in sorted(entry_points(group=READ_GROUP), key=lambda p: p.name):
        loaded = _load(point)
        if not write_half_was_already_here:
            _refuse_write_half_in_the_read_path(point)
        modules.append(loaded)

    modules.sort(key=lambda module: module.name)
    refuse_duplicate_tool_names(modules)
    return tuple(modules)


def _load(point: EntryPoint) -> ReadModule:
    try:
        loaded = point.load()
    except Exception as exc:  # noqa: BLE001 -- re-raised, with the entry point named
        raise ModuleSeamViolation(
            f"read module entry point {point.name!r} = {point.value!r} could not be "
            f"imported: {type(exc).__name__}: {exc}"
        ) from exc
    if not isinstance(loaded, ReadModule):
        raise ModuleSeamViolation(
            f"read module entry point {point.name!r} = {point.value!r} resolved to "
            f"{type(loaded).__name__}, not a postern_core.modules.read.ReadModule"
        )
    return loaded


def _refuse_write_half_in_the_read_path(point: EntryPoint) -> None:
    """Refuse a read module whose import pulled the write protocol in.

    THE ROUTE `.importlinter` CANNOT SEE. Its contracts graph this
    repository's own root packages, so they catch ``services.api`` reaching a
    write half and they catch the in-repo cards module doing it. A module
    installed from outside this tree is in nobody's graph, and the one import
    it needs in order to declare a write operation at all is
    `postern_core.modules.write`. So the read path watches for that import
    appearing while it loads read modules, and refuses.

    RELATIVE, NOT ABSOLUTE, and the difference is what makes it usable: the
    caller records whether the write protocol was already imported before
    loading began. In a read service it never is, so the check is total. In one
    test process that also exercises ``services/confirm`` it already is, and
    the check disarms itself rather than failing on an unrelated import --
    which is why the refusal is measured in a subprocess by
    `tests/test_module_seam_write_half.py`, where nothing else has imported
    anything.

    Raises:
        ModuleSeamViolation: naming the entry point that did it.
    """
    if _WRITE_PROTOCOL in sys.modules:
        raise ModuleSeamViolation(
            f"read module entry point {point.name!r} = {point.value!r} imported "
            f"{_WRITE_PROTOCOL}, so its write half is now in the read process. A "
            "module's write half belongs in a second distribution that only "
            "services/confirm installs: the read process holds a READ signing key "
            "and no write key, and that split is worth nothing if the read image "
            "carries the code that knows which backend endpoint to reach."
        )


def tools_of(modules: Iterable[ReadModule]) -> tuple[tuple[ReadModule, ReadTool], ...]:
    """Flatten modules to (module, tool) pairs, for callers that register or
    serialise every tool and need to name its module in both cases."""
    return tuple((module, tool) for module in modules for tool in module.tools)

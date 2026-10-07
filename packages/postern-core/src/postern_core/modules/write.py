"""The write half of a module: which backend endpoint an approval reaches.

A module's write half declares NO TOOL AND NO HANDLER. It declares routing: for
each write tool name, the backend audience, the path template, the HTTP method
and the verification tier. `services/confirm/callback.py` is what calls the
endpoint, after an operator-side approval carrying an Ed25519 signature over
the stored challenge row. A module cannot supply code that runs on the write
path's request, and that is the design, not a gap: CLAUDE.md's hard rule is
that execution belongs to the approval callback and never to a tool handler,
and a module handler on the write path would be a tool handler by another name.

THIS MODULE IS THE IMPORT `services.api` MUST NEVER MAKE. `.importlinter`'s
``api-not-module-write-half`` contract forbids it, and
`postern_core.modules.read._refuse_write_half_in_the_read_path` watches for it
appearing in `sys.modules` while the read path loads modules. Both exist because
a module's write half has to import something from the host in order to declare
anything, and this is the one thing it has to import -- which makes it the
tripwire a third-party module cannot route around while still declaring a write
operation.

WHY TIER IS DECLARED HERE AND NOT DERIVED. CLAUDE.md: "Declare the verification
tier on the tool definition. Never derive it from the HTTP verb." A module
declaring ``method="POST"`` for a large search body and ``method="PATCH"`` for a
rename says nothing about how hard the customer has to confirm; the tier does,
and `tool-surface.json` records it so a module raising its own operation from
tier 2 to tier 1 shows up in a diff. The tier must be 1 or 2 and is validated
on construction of the `WriteOperation`.
"""

from __future__ import annotations

import dataclasses
import re
import reprlib
from importlib.metadata import EntryPoint, entry_points
from typing import Any

from postern_core.domain.verification import VerificationTier
from postern_core.modules.groups import WRITE_GROUP

__all__ = [
    "WRITE_GROUP",
    "WRITE_METHODS",
    "WriteModule",
    "WriteOperation",
    "WriteSeamViolation",
    "load_write_modules",
]

#: The methods a write operation may use.
#:
#: GET is refused rather than merely unused. A write path that accepted one
#: would be a route through the approval callback -- audit rows, device
#: signature, revocation check and all -- to a backend read endpoint, which is
#: the shape an operator would reach for to "just read one field during
#: approval" and which puts a read through the process holding the write key.
WRITE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})

_TOOL_NAME_RE = re.compile(r"^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)?$")
_PLACEHOLDER_RE = re.compile(r"\{([^{}]*)\}")

#: Caps the repr of a declared tier. The default `reprlib.repr` cuts an
#: arbitrary object's repr at 30 characters, which turns the enum member
#: ``<VerificationTier.SESSION_ONLY: 0>`` into ``<Verification...SSION_ONLY: 0>``
#: and hides which member was declared.
_TIER_REPR = reprlib.Repr(maxother=80, maxstring=80)


class WriteSeamViolation(RuntimeError):
    """A write module declaration the host refuses to serve."""


@dataclasses.dataclass(frozen=True)
class WriteOperation:
    """One approved operation, and the backend endpoint it reaches.

    Attributes:
        tool_name: The MCP tool name stored on the challenge row. The approval
            callback resolves the endpoint from THIS, read back out of the
            database, never from anything the agent sent.
        audience: The backend service audience the internal JWT is minted for,
            e.g. ``cards.svc``. It must have an entry in
            `services/confirm/minter.py`'s `WRITE_SCOPES`, or minting raises --
            which is the key split refusing an audience the write key was not
            given a scope for.
        path_template: The endpoint path. ``{name}`` placeholders are filled
            from the stored challenge payload and from nothing else.
        method: One of `WRITE_METHODS`.
        tier: The verification tier this operation requires. Declared, never
            derived from ``method``. It must be
            ``VerificationTier.APP_APPROVAL`` or
            ``VerificationTier.APP_IDENTITY_VERIFICATION``, and construction
            refuses anything else.
    """

    tool_name: str
    audience: str
    path_template: str
    method: str
    tier: VerificationTier

    def __post_init__(self) -> None:
        if not isinstance(self.tool_name, str):
            raise ValueError(
                f"write operation {self.tool_name!r} is not a usable tool name: it must "
                f"be a string, not {type(self.tool_name).__qualname__}"
            )
        if not _TOOL_NAME_RE.match(self.tool_name):
            raise ValueError(
                f"{self.tool_name!r} is not a usable tool name: lowercase letters, "
                "digits and underscores, at most one dot (e.g. 'cards.freeze_card')"
            )
        if not isinstance(self.tier, VerificationTier) or self.tier < VerificationTier.APP_APPROVAL:
            raise ValueError(
                f"write operation {self.tool_name!r} declares tier "
                f"{_TIER_REPR.repr(self.tier)} ({type(self.tier).__qualname__}); a write "
                "operation declares a VerificationTier member, APP_APPROVAL or "
                "APP_IDENTITY_VERIFICATION"
            )
        if not self.audience:
            raise ValueError(f"write operation {self.tool_name!r} declares no audience")
        if not isinstance(self.audience, str):
            raise ValueError(
                f"write operation {self.tool_name!r} declares audience {self.audience!r}: "
                f"it must be a string, not {type(self.audience).__qualname__}"
            )
        if not isinstance(self.path_template, str):
            raise ValueError(
                f"write operation {self.tool_name!r} has path template "
                f"{self.path_template!r}: it must be a string, not "
                f"{type(self.path_template).__qualname__}"
            )
        if not self.path_template.startswith("/"):
            raise ValueError(
                f"write operation {self.tool_name!r} has path template "
                f"{self.path_template!r}, which is not absolute: it is joined onto the "
                "backend base URL, and a relative path silently resolves against "
                "whatever the base URL's own path happens to be"
            )
        if not isinstance(self.method, str) or self.method not in WRITE_METHODS:
            raise ValueError(
                f"write operation {self.tool_name!r} declares method {self.method!r}; "
                f"a write operation uses one of {sorted(WRITE_METHODS)}"
            )
        for placeholder in _PLACEHOLDER_RE.findall(self.path_template):
            if not placeholder.isidentifier():
                raise ValueError(
                    f"write operation {self.tool_name!r} has path template "
                    f"{self.path_template!r} with placeholder {placeholder!r}, which is "
                    "not an identifier: a placeholder names a field of the stored "
                    "challenge payload"
                )

    @property
    def path_fields(self) -> tuple[str, ...]:
        """The payload fields this operation's path needs, in order."""
        return tuple(_PLACEHOLDER_RE.findall(self.path_template))

    def as_dict(self) -> dict[str, Any]:
        """The surface-file projection. ``tier`` is an int because
        ``tool-surface.json`` is read by a diff and by nothing that would
        benefit from the enum's name being two words long."""
        return {
            "tool_name": self.tool_name,
            "audience": self.audience,
            "path_template": self.path_template,
            "method": self.method,
            "tier": int(self.tier),
        }

    def as_registry_entry(self) -> tuple[str, str, str]:
        """The ``(audience, path_template, method)`` triple
        `services/confirm/execute.py`'s `TOOL_REGISTRY` is keyed on.

        The triple predates this seam and is kept byte-identical rather than
        widened to carry the tier: `services/confirm/execute.py`'s
        `resolve_endpoint` is what reads it, it has never needed the tier, and
        `tests/test_execute.py` pins the exact tuples. The tier reaches the
        surface file from `as_dict` instead.
        """
        return (self.audience, self.path_template, self.method)


@dataclasses.dataclass(frozen=True)
class WriteModule:
    """A module's write half: a name, and the operations it routes.

    Attributes:
        name: The module's own name, matching its read half's, e.g. ``cards``.
        operations: Its write operations. Empty is refused for the same reason
            an empty read module is: an entry point that routes nothing is a
            packaging mistake that would otherwise be silent.
    """

    name: str
    operations: tuple[WriteOperation, ...]

    def __post_init__(self) -> None:
        if not self.name.isidentifier():
            raise ValueError(f"{self.name!r} is not a usable module name: use an identifier")
        if not self.operations:
            raise ValueError(f"write module {self.name!r} declares no operations")
        seen: set[str] = set()
        for operation in self.operations:
            if operation.tool_name in seen:
                raise ValueError(
                    f"write module {self.name!r} declares {operation.tool_name!r} twice"
                )
            seen.add(operation.tool_name)


def load_write_modules() -> tuple[WriteModule, ...]:
    """Every installed write module, sorted by name, or refuse to start.

    No counterpart to `postern_core.modules.read.refuse_distributions_declaring_both_halves`
    is called here, and that asymmetry is deliberate. That check protects the
    READ process from carrying a write half; the write process legitimately
    carries both halves of nothing and one half of everything it routes, and
    refusing a combined distribution here would refuse a deployment that has
    already accepted the consequence. The read path is where the refusal buys
    something, so the read path is where it lives.

    Raises:
        WriteSeamViolation: if an entry point cannot be imported, resolves to
            the wrong type, or two modules route the same tool name.
    """
    modules: list[WriteModule] = []
    for point in sorted(entry_points(group=WRITE_GROUP), key=lambda p: p.name):
        modules.append(_load(point))
    modules.sort(key=lambda module: module.name)

    owner: dict[str, str] = {}
    for module in modules:
        for operation in module.operations:
            if operation.tool_name in owner:
                raise WriteSeamViolation(
                    f"write operation {operation.tool_name!r} is routed by both module "
                    f"{owner[operation.tool_name]!r} and module {module.name!r}. Two "
                    "routes for one tool name would make which backend endpoint an "
                    "approved payment reaches depend on installation order."
                )
            owner[operation.tool_name] = module.name
    return tuple(modules)


def _load(point: EntryPoint) -> WriteModule:
    try:
        loaded = point.load()
    except Exception as exc:  # noqa: BLE001 -- re-raised, with the entry point named
        raise WriteSeamViolation(
            f"write module entry point {point.name!r} = {point.value!r} could not be "
            f"imported: {type(exc).__name__}: {exc}"
        ) from exc
    if not isinstance(loaded, WriteModule):
        raise WriteSeamViolation(
            f"write module entry point {point.name!r} = {point.value!r} resolved to "
            f"{type(loaded).__name__}, not a postern_core.modules.write.WriteModule"
        )
    return loaded

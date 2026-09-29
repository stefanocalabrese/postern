"""The tool surface is checked in, and the build fails when it drifts.

WHAT THIS GATE IS FOR, and it is not documentation. CLAUDE.md's hard rule reads:
"Tool definitions are static config versioned in the repo, never registered at
runtime by backend services. Runtime registration breaks the PrivateLink design
and makes the tool surface impossible to diff between deploys." The module seam
satisfies the first clause -- an entry point is resolved at import out of the
distributions in the image -- and makes the second clause HARDER, because
``git diff`` on this repository no longer shows a surface that installed
distributions can add to. ``tool-surface.json`` is what puts the second clause
back: it is regenerated from the assembled server, so the diff names every tool,
its module, its consent domain, its annotations, its parameters, and every write
operation's backend audience, path, method and verification tier.

WHAT A MODULE ADDITION LOOKS LIKE. This is the diff `make tool-surface` produced
when the ``standing_orders`` module of `tests/test_module_seam.py` was installed
-- the whole change, nothing elided:

    +    {
    +      "module": "standing_orders",
    +      "name": "standing_orders.list",
    +      "consent_domain": "payments",
    +      "read_only_hint": true,
    +      "open_world_hint": false,
    +      "parameters": [],
    +      "required": []
    +    },

A reviewer reading that learns the tool name a client will see, which module
owns it, that it is gated on the ``payments`` consent domain, that it is
annotated read-only and closed-world, and that it takes no arguments -- without
reading the module's code. Removing a module deletes the same block; re-gating
one changes the ``consent_domain`` line; a write operation pointed at a
different backend endpoint changes ``audience`` or ``path_template``, and one
quietly dropped from tier 2 to tier 1 changes ``tier``.

WHAT IT CANNOT SHOW, said here because a green gate must not be read as more
than it is: the file records DECLARATIONS and a schema summary. It says nothing
about what a module's handler does with the data it reads, and nothing about
what else the module's code does in the process -- see
`postern_core.modules`' own docstring, a module is not sandboxed. A module whose
declaration never changes can be rewritten entirely between two versions of its
wheel and this file will not move. Pin your modules by hash.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from postern_core.modules.read import ReadContext, ReadModule, ReadTool, ToolHandler

from tests.tool_surface import (
    SURFACE_PATH,
    declared_read_tools,
    read_surface,
    surface_json,
    write_surface,
)


def test_the_golden_file_exists_and_is_not_empty() -> None:
    """Without this, a deleted or truncated file would make the comparison
    below fail with a diff nobody can read, or pass trivially."""
    assert SURFACE_PATH.exists(), (
        f"{SURFACE_PATH} is missing. Run `make tool-surface` and commit the result."
    )
    assert SURFACE_PATH.read_text().strip(), f"{SURFACE_PATH} is empty"


async def test_the_checked_in_surface_matches_the_assembled_server() -> None:
    """Real failure captured while building this gate, with the cards module's
    consent domain temporarily changed from ``cards`` to ``payments``:

        AssertionError: tool-surface.json is out of date. Run `make
        tool-surface` and review the diff. First difference at line 40:
          checked in: "consent_domain": "cards",
          generated:  "consent_domain": "payments",
    """
    generated = await surface_json()
    checked_in = SURFACE_PATH.read_text()
    if generated == checked_in:
        return
    generated_lines = generated.splitlines()
    checked_lines = checked_in.splitlines()
    # `strict=False` on purpose: the two files may differ in LENGTH, which is
    # the common case when a module is added, and that is reported by the
    # fallback below with both counts. A strict zip would raise `ValueError`
    # here instead, out of a gate whose whole job is to explain the difference.
    for number, (left, right) in enumerate(
        zip(checked_lines, generated_lines, strict=False), start=1
    ):
        if left != right:
            raise AssertionError(
                f"{SURFACE_PATH.name} is out of date. Run `make tool-surface` and "
                f"review the diff. First difference at line {number}:\n"
                f"  checked in: {left.strip()}\n"
                f"  generated:  {right.strip()}"
            )
    raise AssertionError(
        f"{SURFACE_PATH.name} is out of date: it has {len(checked_lines)} lines and "
        f"the assembled server produces {len(generated_lines)}. Run `make tool-surface`."
    )


async def test_every_registered_tool_is_declared_by_a_module() -> None:
    """The half of the gate that is not about the file.

    `tests/tool_surface.py`'s `read_surface` asserts it in both directions, so
    calling it is the assertion. A tool that registered without a declaration
    would be outside the consent domain, outside this file and outside anything
    else that reads declarations; a declared tool that did not register is a
    module whose tools silently did not arrive.
    """
    rows = await read_surface()
    assert {row["name"] for row in rows} == set(declared_read_tools())


def test_the_five_shipped_read_tools_are_the_five_in_the_file() -> None:
    """A belt-and-braces count, because the comparison above would also pass on
    a file regenerated from a server that registered nothing at all."""
    import json

    surface = json.loads(SURFACE_PATH.read_text())
    assert [row["name"] for row in surface["read_tools"]] == [
        "accounts.get_balance",
        "accounts.list",
        "start_session",
        "cards.list",
        "transactions.list",
    ]


def test_the_six_write_operations_are_the_six_in_the_file() -> None:
    import json

    surface = json.loads(SURFACE_PATH.read_text())
    assert {row["tool_name"] for row in surface["write_operations"]} == {
        name for name, _ in ((row["tool_name"], row) for row in write_surface())
    }
    assert len(surface["write_operations"]) == 6


# --- Self-check: the gate is a control, not a decoration ---------------------


def _build(context: ReadContext) -> ToolHandler:
    async def extra_tool() -> list[str]:
        """A tool nothing declared in the golden file."""
        return []

    return extra_tool


async def test_a_module_added_to_the_surface_makes_the_gate_fail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """With `read_surface`'s module set widened by one, the comparison must
    fail. Without this, a `surface_json` that had quietly stopped reading the
    server -- returning the file's own bytes, say -- would pass forever.

    BOTH BINDINGS ARE PATCHED, which is the whole lesson of the first failure
    this test produced:

        AssertionError: declared tools that did not register: ['zzz.extra']

    `services/api/server.py` and `tests/tool_surface.py` each import
    `BUILTIN_READ_MODULES` by value, so patching one widens the declarations
    while the other still registers five tools -- which trips the cross-check
    instead of the file comparison. An installed distribution is seen by both at
    once, so simulating one means patching both. Discovery against a real
    ``.dist-info`` is `tests/test_module_seam.py`'s job; this test is about the
    gate.
    """
    import services.api.server as server_module
    import tests.tool_surface as surface_module
    from services.api.tools import BUILTIN_READ_MODULES

    extra = ReadModule(
        name="zzz_surface_selfcheck",
        tools=(ReadTool(name="zzz.extra", consent_domain="cards", build=_build),),
    )
    widened = BUILTIN_READ_MODULES + (extra,)
    monkeypatch.setattr(surface_module, "BUILTIN_READ_MODULES", widened, raising=True)
    monkeypatch.setattr(server_module, "BUILTIN_READ_MODULES", widened, raising=True)
    with pytest.raises(AssertionError, match="out of date"):
        await test_the_checked_in_surface_matches_the_assembled_server()


async def test_the_declaration_check_catches_a_tool_registered_behind_its_back(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The other direction: a server carrying a tool no module declared.

    Simulated by narrowing what `read_surface` considers declared, which is the
    same observable condition -- registered set minus declared set is non-empty
    -- as a module registering a tool it never declared.
    """
    import tests.tool_surface as surface_module

    monkeypatch.setattr(surface_module, "BUILTIN_READ_MODULES", (), raising=True)
    with pytest.raises(AssertionError, match="no module declaration"):
        await read_surface()


def test_the_golden_file_is_at_the_repository_root() -> None:
    """Where a reviewer trips over it. A surface file inside ``tools/`` or
    ``docs/`` is one a reviewer has to know to look at."""
    assert SURFACE_PATH.parent == Path(__file__).resolve().parents[1]
    assert SURFACE_PATH.name == "tool-surface.json"

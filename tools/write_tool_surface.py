#!/usr/bin/env python3
"""Regenerate ``tool-surface.json``. Run by ``make tool-surface``.

The gate is `tests/test_tool_surface_golden.py`, which fails when the checked-in
file disagrees with the assembled server. This script is how you make them agree
again, and the diff it produces is the artefact: it names every tool a module
added, renamed or re-gated, and every backend endpoint a write operation routes.

Everything it does lives in `tests/tool_surface.py`, for the reason that module's
docstring gives -- it is the only place in this tree that may import both
services, and unlike ``tools/`` it is inside ``make ci``'s mypy and ruff runs.
"""

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tests.tool_surface import SURFACE_PATH, surface_json  # noqa: E402


def main() -> int:
    generated = asyncio.run(surface_json())
    previous = SURFACE_PATH.read_text() if SURFACE_PATH.exists() else ""
    SURFACE_PATH.write_text(generated)
    if generated == previous:
        print(f"{SURFACE_PATH.name} unchanged")
    else:
        print(f"{SURFACE_PATH.name} rewritten -- review `git diff {SURFACE_PATH.name}`")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

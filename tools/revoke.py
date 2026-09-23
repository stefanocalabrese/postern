#!/usr/bin/env python3
"""ZT-7 revocation, from an operator's shell.

A shim. Everything -- argument parsing, the store, the operational procedure,
and what a revocation does and does not stop -- lives in
`postern_core.auth.revoke_cli`, because `make type` runs mypy over
``packages services tests`` and ``ruff format --check`` over the same three,
so logic left in this directory is neither type-checked nor format-checked.

    POSTERN_REDIS_URL=rediss://... uv run python tools/revoke.py list
"""

import sys

from postern_core.auth.revoke_cli import main

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

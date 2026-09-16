"""`fileConfig`'s `disable_existing_loggers` regression (migrations/env.py).

`logging.config.fileConfig` defaults `disable_existing_loggers` to `True`,
which sets `.disabled = True` on every logger that already exists in the
process, for the rest of that process's life. Harmless when `alembic
upgrade` runs in its own process; not harmless when it runs in-process at
application startup, which silences every logger the application created
before that call -- including one about to report that the audit store is
unreachable.

Isolation is the hard part here, not the assertion. `fileConfig` mutates
process-wide logging state (handlers, levels, every existing logger's
`.disabled` flag). Running it in-process, even wrapped in
save-and-restore, risks a partial restore that leaves later tests in this
same pytest session silently reconfigured -- a worse bug than the one this
test is guarding against. This test spawns a subprocess instead: a fresh
interpreter creates a logger, then execs the *exact* guard-and-call block
this repo's migrations/env.py runs, against this repo's real alembic.ini,
and reports back whether the logger survived. Nothing about process-wide
logging state in the pytest process itself is ever touched.

The block is pulled out of migrations/env.py by source position (`ast`),
not retyped, so a future edit that drops the `disable_existing_loggers=False`
keyword breaks this test by changing what it executes, rather than leaving
a hand-copied duplicate that keeps passing regardless of what env.py
actually does.
"""

import ast
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
ENV_PY = REPO_ROOT / "migrations" / "env.py"


def _fileconfig_guard_block() -> str:
    """Return the exact source text of the `if config.config_file_name ...:
    fileConfig(...)` statement in migrations/env.py.

    Walks the module in file order and returns the first `if` block whose
    body calls `fileConfig`, so this keeps working across unrelated edits
    to env.py (new imports, reordered sections) as long as that block
    exists at all; if it is ever removed, `RuntimeError` below fires and
    names the missing file precisely, rather than a bare `IndexError` or a
    silently-empty exec block.
    """
    source = ENV_PY.read_text()
    tree = ast.parse(source, filename=str(ENV_PY))
    for node in ast.walk(tree):
        if isinstance(node, ast.If):
            segment = ast.get_source_segment(source, node)
            if segment is not None and "fileConfig" in segment:
                return segment
    raise RuntimeError(f"no fileConfig guard found in {ENV_PY}")


def _run_fileconfig_guard_in_subprocess() -> subprocess.CompletedProcess[str]:
    """Exec the extracted guard block in a fresh interpreter, cwd'd to the
    repo root so `config.config_file_name` ("alembic.ini") resolves to this
    repo's real file -- the same relative-path resolution `alembic upgrade`
    itself relies on and that migrations/conftest.py's `Config("alembic.ini")`
    already depends on.
    """
    script = f"""
import logging
import os
from logging.config import fileConfig

from alembic.config import Config

logger = logging.getLogger("postern.test.pre_existing_logger")
assert logger.disabled is False, "probe logger should start out enabled"

config = Config("alembic.ini")

{_fileconfig_guard_block()}

# Confirms fileConfig actually ran against this repo's real alembic.ini
# (which sets [logger_alembic] level = INFO) rather than the guard's
# os.path.exists check silently taking the False branch and skipping
# fileConfig entirely -- that would also leave the probe logger enabled,
# for the wrong reason.
alembic_level = logging.getLogger("alembic").level
print(f"disabled={{logger.disabled}} alembic_level={{alembic_level}}")
"""
    return subprocess.run(  # noqa: S603 -- fixed argv, no shell, script built from this repo's own source above
        [sys.executable, "-c", script],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=30,
    )


def test_fileconfig_does_not_disable_pre_existing_loggers() -> None:
    result = _run_fileconfig_guard_in_subprocess()
    assert result.returncode == 0, result.stderr
    assert "disabled=False" in result.stdout, result.stdout
    # logging.INFO == 20; asserted numerically since the subprocess only
    # has stdlib `logging` imported, matching [logger_alembic] in
    # alembic.ini, proving fileConfig really parsed this repo's real ini
    # and not a no-op or a synthetic stand-in.
    assert "alembic_level=20" in result.stdout, result.stdout

"""A module's write half cannot reach the read path. Three layers, each measured.

THE PROPERTY. `services/api` holds the READ signing key and `services/confirm`
the WRITE key, and a module that adds a write operation has two halves loading
into two different processes. If a module can get its write half into the read
process, the split stops being an infrastructure property and becomes a
code-review promise, which is exactly what CLAUDE.md says it must not be.

Three things enforce it, and they fail in three different places, because each
one is blind to what the next one sees:

1. `.importlinter`, at ``make imports``. Its ``api-not-module-write-half``
   contract forbids ``services.api`` from reaching `postern_core.modules.write`
   or `postern_cards_write`. Observed BROKEN on 2026-09-29 by appending
   ``from postern_core.modules.write import WriteOperation`` to
   `services/api/server.py`:

       The API service must not import any module write half BROKEN

   WHAT IT CANNOT SEE: a distribution installed from outside this tree, because
   import-linter graphs only the root packages the config lists.

2. `postern_core.modules.read._refuse_write_half_in_the_read_path`, at
   composition. That is what this file measures. Any write half must import
   `postern_core.modules.write` to declare an operation at all, so the read
   loader watches for that module appearing in `sys.modules` while it loads read
   modules, and refuses. It catches the out-of-repo case layer 1 is blind to.

   WHAT IT CANNOT SEE: a write half whose code is present but never imported
   during loading. It is a tripwire on an import, not a scan of what is
   installed.

3. The Dockerfile, at build. `tests/test_module_halves_in_images.py` asserts the
   api image copies no module's write-half source, so the read container does not
   contain the code even if something tried to import it.

   WHAT IT CANNOT SEE: what a built image actually holds, as
   `tests/test_image_service_split.py` says at length about itself. It parses
   instructions.

WHY A SUBPROCESS. Layer 2 is deliberately RELATIVE: it records whether
`postern_core.modules.write` was already imported before loading began, and
disarms itself if it was. In a read service it never is. In this test process it
IS -- `tests/test_execute.py` imports `services/confirm/execute.py`, which
imports the write protocol, and pytest shares one interpreter -- so measuring
the refusal here in-process would depend on test collection order, which is not
a measurement. Each test below runs a clean interpreter that has imported
nothing.
"""

from __future__ import annotations

import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

#: What the subprocess does: load read modules, print what it found, exit 0.
#:
#: `load_read_modules` and nothing else, so a non-zero exit is the loader's
#: refusal and not a side effect of assembling a server.
_LOADER = textwrap.dedent(
    """
    import sys
    from postern_core.modules.read import load_read_modules
    modules = load_read_modules()
    print("LOADED", sorted(m.name for m in modules))
    print("WRITE_PROTOCOL_IMPORTED", "postern_core.modules.write" in sys.modules)
    """
)

_CLEAN_HALF = '''
"""A read half that imports only the read protocol."""

from typing import Any

from postern_core.modules.read import ReadContext, ReadModule, ReadTool


def _build(ctx: ReadContext) -> Any:
    async def clean_list() -> list[str]:
        """Return nothing."""
        return []

    return clean_list


MODULE = ReadModule(
    name="clean",
    tools=(ReadTool(name="clean.list", consent_domain="cards", build=_build),),
)
'''

_SMUGGLING_HALF = '''
"""A read half that also carries its own write routing.

This is the shape the refusal exists for: one importable module declaring a
read tool AND reaching for the write protocol, so that installing the read half
installs backend write routing into the process holding the read key.
"""

from typing import Any

from postern_core.domain.verification import VerificationTier
from postern_core.modules.read import ReadContext, ReadModule, ReadTool
from postern_core.modules.write import WriteModule, WriteOperation

WRITE = WriteModule(
    name="smuggler",
    operations=(
        WriteOperation(
            tool_name="smuggler.pay",
            audience="payments.svc",
            path_template="/payments",
            method="POST",
            tier=VerificationTier.APP_APPROVAL,
        ),
    ),
)


def _build(ctx: ReadContext) -> Any:
    async def smuggler_list() -> list[str]:
        """Return nothing."""
        return []

    return smuggler_list


MODULE = ReadModule(
    name="smuggler",
    tools=(ReadTool(name="smuggler.list", consent_domain="cards", build=_build),),
)
'''


def _install(root: Path, *, dist_name: str, module_name: str, source: str) -> None:
    (root / f"{module_name}.py").write_text(source)
    info = root / f"{dist_name.replace('-', '_')}-0.0.0.dist-info"
    info.mkdir()
    (info / "METADATA").write_text(f"Metadata-Version: 2.1\nName: {dist_name}\nVersion: 0.0.0\n")
    (info / "entry_points.txt").write_text(
        f"[postern.read_modules]\n{module_name} = {module_name}:MODULE\n"
    )


def _run_loader(extra_path: Path) -> subprocess.CompletedProcess[str]:
    """Load read modules in a clean interpreter with ``extra_path`` installed."""
    return subprocess.run(  # noqa: S603 -- sys.executable and a literal script
        [sys.executable, "-c", _LOADER],
        capture_output=True,
        text=True,
        env={
            "PATH": "/usr/bin:/bin",
            "PYTHONPATH": str(extra_path),
            "PYTHONDONTWRITEBYTECODE": "1",
        },
        cwd=str(Path(__file__).resolve().parents[1]),
        timeout=60,
    )


def test_the_control_a_clean_read_half_loads_and_exits_zero(tmp_path: Path) -> None:
    """THE CONTROL, and without it the refusal below proves nothing: a
    subprocess that fails for any reason -- a missing interpreter, an unimportable
    `postern_core`, a typo in the script -- would satisfy an exit-code assertion
    just as well as the refusal does.

    It also pins the second half of the relative check: a clean read half must
    leave ``postern_core.modules.write`` UNIMPORTED, which is what makes the
    tripwire meaningful in a real read process.
    """
    _install(tmp_path, dist_name="fixture-clean", module_name="fixture_clean", source=_CLEAN_HALF)
    result = _run_loader(tmp_path)
    assert result.returncode == 0, f"stdout={result.stdout!r} stderr={result.stderr!r}"
    assert "LOADED ['cards', 'clean']" in result.stdout, result.stdout
    assert "WRITE_PROTOCOL_IMPORTED False" in result.stdout, result.stdout


def test_a_read_half_that_imports_the_write_protocol_is_refused(tmp_path: Path) -> None:
    """The measurement. Real failure captured on 2026-09-29, verbatim from the
    subprocess's stderr:

        postern_core.modules.read.ModuleSeamViolation: read module entry point
        'fixture_smuggler' = 'fixture_smuggler:MODULE' imported
        postern_core.modules.write, so its write half is now in the read
        process.

    The message names the entry point, which is what an operator needs: they
    installed a wheel, and the refusal has to say which one.
    """
    _install(
        tmp_path,
        dist_name="fixture-smuggler",
        module_name="fixture_smuggler",
        source=_SMUGGLING_HALF,
    )
    result = _run_loader(tmp_path)
    assert result.returncode != 0, f"stdout={result.stdout!r}"
    assert "ModuleSeamViolation" in result.stderr, result.stderr
    assert "fixture_smuggler" in result.stderr, result.stderr
    assert "postern_core.modules.write" in result.stderr, result.stderr


def test_the_refusal_happens_before_any_tool_is_registered(tmp_path: Path) -> None:
    """It refuses at composition, so nothing was served.

    The loader prints ``LOADED`` only on success, so its absence is the
    assertion: the process died while loading modules and never reached the line
    that would have reported a surface.
    """
    _install(
        tmp_path,
        dist_name="fixture-smuggler",
        module_name="fixture_smuggler",
        source=_SMUGGLING_HALF,
    )
    result = _run_loader(tmp_path)
    assert "LOADED" not in result.stdout, result.stdout


def test_building_the_real_read_server_never_imports_the_write_protocol() -> None:
    """The shipped read path, measured rather than argued.

    `services/api/server.py`'s `build_server` over the installed module set --
    `postern_cards` included -- must leave the write protocol unimported. This is
    the assertion `.importlinter` makes statically, taken again at runtime, which
    is where an entry point resolves.
    """
    script = textwrap.dedent(
        """
        import sys

        import httpx2
        from postern_core.facade.client import BackendClient, StubTokenMinter

        from services.api.server import build_server
        from services.api.settings import Settings
        from postern_core.identity import CustomerRef

        backend = BackendClient(
            "https://backend.test",
            StubTokenMinter(),
            transport=httpx2.MockTransport(lambda r: httpx2.Response(404, json={})),
            before_backend_request=None,
        )
        server = build_server(
            Settings.for_testing(),
            resolver=lambda: CustomerRef(value="cust_7f3a"),
            backend=backend,
        )
        assert "postern_core.modules.write" not in sys.modules, "write protocol imported"
        assert "postern_cards_write" not in sys.modules, "cards write half imported"
        assert "services.confirm" not in sys.modules, "confirm service imported"
        print("CLEAN")
        """
    )
    result = subprocess.run(  # noqa: S603 -- sys.executable and a literal script
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        env={"PATH": "/usr/bin:/bin", "PYTHONPATH": ".", "PYTHONDONTWRITEBYTECODE": "1"},
        cwd=str(Path(__file__).resolve().parents[1]),
        timeout=60,
    )
    assert result.returncode == 0, f"stdout={result.stdout!r} stderr={result.stderr!r}"
    assert "CLEAN" in result.stdout


@pytest.mark.parametrize("group", ["postern.read_modules", "postern.write_modules"])
def test_the_two_entry_point_groups_are_declared_by_different_distributions(group: str) -> None:
    """The in-repo cards module obeys "one module, two distributions".

    Read off the live environment rather than the two ``pyproject.toml`` files,
    because what matters is what is installed.
    """
    from importlib.metadata import entry_points

    declaring = {point.dist.name for point in entry_points(group=group) if point.dist is not None}
    assert declaring, f"nothing declares {group}"
    other = "postern.write_modules" if group == "postern.read_modules" else "postern.read_modules"
    other_declaring = {
        point.dist.name for point in entry_points(group=other) if point.dist is not None
    }
    assert not (declaring & other_declaring), (
        f"these distributions declare both groups: {sorted(declaring & other_declaring)}"
    )

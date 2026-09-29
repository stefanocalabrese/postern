"""Each serving image carries one half of every module, and it is the right half.

THE CONTROL. `.importlinter` says ``services.api`` does not IMPORT a module's
write half. That is a statement about source, and `tests/test_image_service_split.py`
records at length what happened the last time this project relied on a source
statement to describe an image: until 26 September 2026 the read image carried
all fifteen modules of the write path, because the runtime stage copied a tree.
A module pair reintroduces exactly that shape -- two source directories, either
of which a stage could copy by accident -- so the rule gets its own gate.

DERIVED, NOT LISTED. The module pairs come out of ``packages/`` by reading which
``pyproject.toml`` declares which entry-point group, so a second module pair
added tomorrow is held to the same rule without this file being edited. A pair
this file cannot classify fails rather than being skipped, which is what stops
a new package silently escaping.

WHAT THIS ESTABLISHES AND WHAT IT DOES NOT. It parses the Dockerfile, so it
proves what the build is instructed to do. It cannot prove what a built image
contains: a base image that already carried the module, a ``.dockerignore``
change altering what the builder's ``COPY . .`` picks up, a volume mounted over
``/app`` at run time, or a registry serving a different layer under a tag would
each make the instructions right and the image wrong. That gap is the same one
`tests/test_image_service_split.py` names about itself, closed the same way:
by hand, when the copy layer changes.

THE MECHANISM THE ABSENCE RELIES ON, stated because it is not obvious. `uv sync`
installs each workspace member editable, so ``site-packages`` holds a
``postern_cards_write.pth`` naming a source directory rather than the package's
code. The api image copies the venv whole -- the ``.pth`` and the
``.dist-info`` with its ``entry_points.txt`` come along -- and does not copy that
source directory, so the import fails. The entry point remains *listed* in the
read image and is never *resolved*, because `services/api` reads only the read
group. `postern_core.modules.read.refuse_distributions_declaring_both_halves` is
what stops the other arrangement, where one wheel's code lands in
``site-packages`` and no Dockerfile decision can keep it out.
"""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass
from pathlib import Path

import pytest
from postern_core.modules.groups import READ_GROUP, WRITE_GROUP

_REPO_ROOT = Path(__file__).resolve().parents[1]
_DOCKERFILE = _REPO_ROOT / "Dockerfile"
_PACKAGES = _REPO_ROOT / "packages"

# `FROM <image-or-stage> [AS <name>]`, matching `tests/test_image_service_split.py`.
_FROM_RE = re.compile(r"^FROM\s+(?P<base>\S+)(?:\s+AS\s+(?P<name>\S+))?$", re.IGNORECASE)
_CONTINUATION_RE = re.compile(r"\\\s*\n\s*")

#: A copy source naming one package's source tree: `/app/packages/<name>/src`.
_PACKAGE_SRC_RE = re.compile(r"^/app/packages/(?P<name>[A-Za-z0-9_.-]+)/src/?$")


@dataclass(frozen=True)
class _Package:
    """One distribution under ``packages/``, and which seam groups it declares."""

    directory: str
    dist_name: str
    declares_read: bool
    declares_write: bool

    @property
    def kind(self) -> str:
        if self.declares_read and self.declares_write:
            return "both"
        if self.declares_read:
            return "read-half"
        if self.declares_write:
            return "write-half"
        return "library"


def _packages() -> tuple[_Package, ...]:
    out: list[_Package] = []
    for manifest in sorted(_PACKAGES.glob("*/pyproject.toml")):
        data = tomllib.loads(manifest.read_text())
        project = data.get("project", {})
        entry_points = project.get("entry-points", {})
        out.append(
            _Package(
                directory=manifest.parent.name,
                dist_name=project.get("name", manifest.parent.name),
                declares_read=READ_GROUP in entry_points,
                declares_write=WRITE_GROUP in entry_points,
            )
        )
    return tuple(out)


def _logical_lines() -> list[str]:
    joined = _CONTINUATION_RE.sub(" ", _DOCKERFILE.read_text())
    return [
        line.strip()
        for line in joined.splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]


def _package_sources_per_stage() -> dict[str, set[str]]:
    """Which package source trees each stage copies, by package directory name.

    Includes what a stage inherits from the stage it is built on, because a
    ``FROM runtime`` stage carries everything ``runtime`` copied.
    """
    own: dict[str, set[str]] = {}
    base: dict[str, str] = {}
    stage: str | None = None
    for line in _logical_lines():
        match = _FROM_RE.match(line)
        if match is not None:
            stage = match.group("name")
            if stage is not None:
                own.setdefault(stage, set())
                base[stage] = match.group("base")
            continue
        if stage is None or not line.upper().startswith("COPY "):
            continue
        for token in line.split()[1:-1]:
            if token.startswith("--"):
                continue
            source_match = _PACKAGE_SRC_RE.match(token)
            if source_match is not None:
                own[stage].add(source_match.group("name"))

    resolved: dict[str, set[str]] = {}
    for name in own:
        carried: set[str] = set()
        current: str | None = name
        seen: set[str] = set()
        while current is not None and current in own and current not in seen:
            seen.add(current)
            carried |= own[current]
            current = base.get(current)
        resolved[name] = carried
    return resolved


def test_the_packages_tree_is_a_shape_this_file_can_read() -> None:
    """Without this, a rename under ``packages/`` would make every assertion
    below pass over an empty list."""
    packages = _packages()
    assert packages, "no distribution found under packages/"
    assert any(p.kind == "read-half" for p in packages), (
        "no package declares a read half; either the seam regressed or this file "
        f"cannot read the manifests: {[(p.directory, p.kind) for p in packages]}"
    )
    assert any(p.kind == "write-half" for p in packages), "no package declares a write half"
    stages = _package_sources_per_stage()
    assert stages, "no build stage was parsed out of the Dockerfile"


def test_no_package_declares_both_halves() -> None:
    """The manifest half of "one module, two distributions".

    `tests/test_module_seam_write_half.py` asserts the same thing against the
    LIVE environment, which is the one that matters; this one fails at the
    manifest, where the mistake is made.
    """
    offenders = [p.directory for p in _packages() if p.kind == "both"]
    assert not offenders, (
        f"these packages declare both {READ_GROUP} and {WRITE_GROUP}: {offenders}. A "
        "module ships as two distributions, because site-packages is copied whole "
        "into both service images."
    )


def test_the_api_image_carries_no_module_write_half() -> None:
    """The read container must not contain write routing.

    Real failure captured while building this gate, with the write half's source
    copy temporarily added to the `api` stage:

        AssertionError: the `api` image copies module write halves
        ['postern-cards-write']. A module's write half names the backend
        audience, path and method an approved operation reaches; the read
        container holds a READ signing key and has no use for it.
    """
    write_halves = {p.directory for p in _packages() if p.kind == "write-half"}
    carried = _package_sources_per_stage().get("api", set())
    offenders = sorted(carried & write_halves)
    assert not offenders, (
        f"the `api` image copies module write halves {offenders}. A module's write "
        "half names the backend audience, path and method an approved operation "
        "reaches; the read container holds a READ signing key and has no use for it."
    )


def test_the_confirm_image_carries_no_module_read_half() -> None:
    """And the mirror. The write container has no MCP surface, so a module's
    read half in it is code nothing can call, sharing a process with the write
    key."""
    read_halves = {p.directory for p in _packages() if p.kind == "read-half"}
    carried = _package_sources_per_stage().get("confirm", set())
    offenders = sorted(carried & read_halves)
    assert not offenders, f"the `confirm` image copies module read halves {offenders}"


@pytest.mark.parametrize("stage,kind", [("api", "read-half"), ("confirm", "write-half")])
def test_each_serving_image_carries_the_half_it_needs(stage: str, kind: str) -> None:
    """The other direction, and the one a pure absence rule would miss: an image
    that copies neither half of a module starts fine and serves a tool surface
    silently missing that module, because `importlib.metadata` still lists the
    entry point whose source is gone.

    A module whose half is deliberately not shipped in an image is a real
    deployment choice, and it belongs in the Dockerfile as a visible omission
    with this gate updated -- not as a copy nobody noticed was missing.
    """
    expected = {p.directory for p in _packages() if p.kind == kind}
    carried = _package_sources_per_stage().get(stage, set())
    missing = sorted(expected - carried)
    assert not missing, (
        f"the `{stage}` image copies no source for {missing}, whose entry point the "
        "venv still declares. The service starts and that module's tools are absent."
    )


def test_the_migration_image_carries_no_module_at_all() -> None:
    """It answers no requests and routes nothing. A module in it is code with
    a database URL holding DDL rights beside it."""
    module_packages = {p.directory for p in _packages() if p.kind in ("read-half", "write-half")}
    carried = _package_sources_per_stage().get("migrate", set())
    offenders = sorted(carried & module_packages)
    assert not offenders, f"the `migrate` image copies module packages {offenders}"


def test_the_builder_copies_every_workspace_manifest() -> None:
    """A workspace member whose ``pyproject.toml`` is missing from the builder's
    first layer is one uv cannot resolve, so the build fails there rather than
    shipping an image without it. Asserted because the failure mode if this
    regresses is a broken build that looks like a lockfile problem.
    """
    copied = {
        token
        for line in _logical_lines()
        if line.upper().startswith("COPY ")
        for token in line.split()[1:-1]
        if token.endswith("pyproject.toml")
    }
    for package in _packages():
        assert f"packages/{package.directory}/pyproject.toml" in copied, (
            f"the builder stage never copies packages/{package.directory}/pyproject.toml, "
            "so `uv sync` cannot resolve that workspace member"
        )

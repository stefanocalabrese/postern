"""The shipped images carry one service each, not both.

`.importlinter` proves `services.api` and `services.confirm` do not import one
another. That is a statement about source. The image is where it stops being
one: until 26 September 2026 the runtime stage did ``COPY --from=builder /app
/app`` and both targets inherited it, so the read image carried all fifteen
modules of the write path -- the device grant, the approval callback that
reaches a backend write endpoint, the write-token minter -- and the read
container's threat model quietly depended on nobody looking.

WHAT THIS FILE CAN AND CANNOT ESTABLISH

It parses the Dockerfile. It therefore proves what the build is *instructed*
to do, and it proves that for every stage at once, including stages added
after this was written. It does not prove what a built image *contains*.
Those differ whenever the instructions are right and something else is wrong:
a base image that already carries the other service, a `.dockerignore` change
that alters what `COPY . .` picks up in the builder, a volume mounted over
`/app` at run time, or a registry serving a different layer under a tag.

Only running the built image settles those, and a build inside `make ci`
would add minutes to a gate that finishes in about 150 seconds. So the
evidence is split deliberately: the assertions below run every time, and the
image-level proof is taken by hand when the copy layer changes. It was taken
on 26 September 2026, and recorded there: `/app/services/confirm` absent from
the `api` image, `/app/services/api` absent from the `confirm` image, and
``importlib.import_module`` raising ``ModuleNotFoundError`` for every module
of the other service in each.

The cheap way to close the gap, not built here because it needs a place to
run rather than more code: the deploy workflow already builds both images on
every dispatch, so one step per image asserting the other service's directory
is absent would make it a hard gate at the only moment the images exist,
without costing `make ci` anything.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
_DOCKERFILE = _REPO_ROOT / "Dockerfile"
_SERVICES_DIR = _REPO_ROOT / "services"

# `FROM <image-or-stage> [AS <name>]`.
_FROM_RE = re.compile(r"^FROM\s+(?P<base>\S+)(?:\s+AS\s+(?P<name>\S+))?$", re.IGNORECASE)

# A copy source naming one service package: `/app/services/<name>`.
_SERVICE_SRC_RE = re.compile(r"^/app/services/(?P<name>[A-Za-z0-9_]+)/?$")

# Copy sources that hand a stage the whole tree, and with it every service.
# `/app/services` is here for the same reason `/app` is: it is the directory
# holding all of them, so copying it copies both.
_WHOLESALE_SRCS = frozenset({".", "./", "/app", "/app/", "/app/services", "/app/services/"})

# A line continued onto the next one.
_CONTINUATION_RE = re.compile(r"\\\s*\n\s*")


@dataclass(frozen=True)
class _Stage:
    """One `FROM` block: what it builds on, what it copies, what it runs."""

    name: str
    base: str
    copy_sources: tuple[str, ...]
    cmd: str | None


def _logical_lines(text: str) -> list[str]:
    """Return the Dockerfile's instructions, joined and stripped of comments."""
    joined = _CONTINUATION_RE.sub(" ", text)
    return [
        line.strip()
        for line in joined.splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]


def _copy_sources(arguments: str) -> tuple[str, ...]:
    """Return a COPY's source operands, dropping its flags and destination."""
    tokens = [token for token in arguments.split() if not token.startswith("--")]
    return tuple(tokens[:-1]) if len(tokens) > 1 else ()


def _stages() -> list[_Stage]:
    """Return every named stage in the Dockerfile, in file order."""
    stages: list[_Stage] = []
    name = base = None
    copies: list[str] = []
    cmd: str | None = None

    def flush() -> None:
        if name is not None and base is not None:
            stages.append(_Stage(name, base, tuple(copies), cmd))

    for line in _logical_lines(_DOCKERFILE.read_text()):
        verb, _, arguments = line.partition(" ")
        match = _FROM_RE.match(line)
        if match is not None:
            flush()
            name, base = match.group("name"), match.group("base")
            copies, cmd = [], None
        elif verb.upper() == "COPY":
            copies.extend(_copy_sources(arguments))
        elif verb.upper() == "CMD":
            cmd = arguments
    flush()
    return stages


def _repo_services() -> set[str]:
    """Return the service packages that exist, read off the tree."""
    return {
        entry.name
        for entry in _SERVICES_DIR.iterdir()
        if entry.is_dir() and (entry / "__init__.py").exists()
    }


def _chain(stage: _Stage, by_name: dict[str, _Stage]) -> list[_Stage]:
    """Return a stage and every stage it is built on, nearest first."""
    out, current, seen = [stage], stage, {stage.name}
    while current.base in by_name and current.base not in seen:
        current = by_name[current.base]
        seen.add(current.name)
        out.append(current)
    return out


def _services_visible(
    stage: _Stage, by_name: dict[str, _Stage], all_services: set[str]
) -> set[str]:
    """Return every service package a stage ends up holding."""
    visible: set[str] = set()
    for member in _chain(stage, by_name):
        for source in member.copy_sources:
            if source in _WHOLESALE_SRCS:
                visible |= all_services
                continue
            match = _SERVICE_SRC_RE.match(source)
            if match is not None:
                visible.add(match.group("name"))
    return visible


def _shipped_stages() -> tuple[list[_Stage], dict[str, _Stage]]:
    """Return the stages that become images, and every stage by name.

    A stage is shipped when nothing else builds on it and nothing copies out
    of it. Derived rather than listed, so a third target added tomorrow is
    held to the same rules without this file being edited.
    """
    stages = _stages()
    by_name = {stage.name: stage for stage in stages}
    consumed = {stage.base for stage in stages}
    for line in _logical_lines(_DOCKERFILE.read_text()):
        consumed |= set(re.findall(r"--from=(\S+)", line))
    return [stage for stage in stages if stage.name not in consumed], by_name


def test_the_dockerfile_declares_stages_this_file_can_read() -> None:
    """Parsing succeeded and found something to check.

    Without this, a Dockerfile rewritten into a shape the parser does not
    recognise would make every assertion below pass over an empty list.
    """
    stages = _stages()
    assert stages, "no named build stage was parsed out of the Dockerfile"
    shipped, _ = _shipped_stages()
    assert shipped, (
        "Every stage is consumed by another one, so nothing is shipped. Either "
        "the Dockerfile has no target stages or this file failed to parse it."
    )
    assert _repo_services(), "no service package found under services/"


def test_no_shipped_stage_carries_more_than_one_service() -> None:
    """Each image holds one service package. This is the whole point.

    Stated over every shipped stage against every service that exists, both
    derived, so adding `services/admin` or a third target does not leave a
    test that passes while an image carries two.
    """
    shipped, by_name = _shipped_stages()
    all_services = _repo_services()

    for stage in shipped:
        visible = _services_visible(stage, by_name, all_services)
        assert visible, (
            f"The `{stage.name}` image carries no service package at all. It "
            "cannot run anything; check what its stage chain copies."
        )
        assert len(visible) == 1, (
            f"The `{stage.name}` image carries {sorted(visible)}. An RCE in one "
            "service's container must not find the other's code, and that is a "
            "property of what this stage copies and of nothing else -- "
            "`.importlinter` proves the source separation and an image built "
            "this way discards the result."
        )


def test_no_shipped_stage_copies_a_whole_tree() -> None:
    """No stage that becomes an image copies `/app`, `/app/services` or `.`.

    The single-service assertion above catches a wholesale copy today because
    two services exist. It would stop catching it the moment one of them was
    removed, and a wholesale copy is wrong then too: it is how `.grimp_cache`
    (this project's full import graph) and `.remember` (session logs) reached
    the built image. Named paths fail closed; a tree fails open.
    """
    shipped, by_name = _shipped_stages()

    offenders: list[str] = []
    for stage in shipped:
        for member in _chain(stage, by_name):
            for source in member.copy_sources:
                if source in _WHOLESALE_SRCS:
                    offenders.append(f"`{stage.name}` (via stage `{member.name}`) copies {source}")
    assert not offenders, (
        "A shipped image is built by copying a whole tree:\n  "
        + "\n  ".join(offenders)
        + "\nCopy the named paths the service needs instead. Whatever is not "
        "named is then absent whether or not `.dockerignore` remembers it."
    )


def test_each_shipped_stage_runs_the_service_it_carries() -> None:
    """The command a stage runs names the one service package it holds.

    Catches the pairing the count cannot: a stage carrying `confirm` while
    running `services.api.main:app` holds exactly one service and starts by
    importing a module that is not there.
    """
    shipped, by_name = _shipped_stages()
    all_services = _repo_services()

    for stage in shipped:
        assert stage.cmd, f"The `{stage.name}` stage declares no CMD, so the image starts nothing."
        visible = _services_visible(stage, by_name, all_services)
        (carried,) = visible
        assert f"services.{carried}." in stage.cmd, (
            f"The `{stage.name}` image carries `services/{carried}` but its "
            f"command does not run it: {stage.cmd}. One of the two is wrong, and "
            "the container finds out at startup."
        )

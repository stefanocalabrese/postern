"""Each shipped image carries one service, and only one of them can migrate.

Two controls, both of which the source tree alone cannot hold, and both of
which were false in a built image at some point in the last two days.

THE SERVICE SPLIT. `.importlinter` proves `services.api` and
`services.confirm` do not import one another. That is a statement about
source. The image is where it stopped being one: until 26 September 2026 the
runtime stage did ``COPY --from=builder /app /app`` and both targets
inherited it, so the read image carried all fifteen modules of the write path
-- the device grant, the approval callback that reaches a backend write
endpoint, the write-token minter -- and the read container's threat model
quietly depended on nobody looking.

THE MIGRATION RUNNER. Fixing that left a second pairing behind. Both serving
images still carried `migrations/` and, inside the virtualenv rather than as
a copied path, the `alembic` console script. The api service holds
`POSTERN_DATABASE_URL` because it needs one, so the scripts, the runner and
the credential sat in one container. Revision `f1860c110112` is what makes
`audit_log` refuse UPDATE, DELETE and TRUNCATE, and its own `downgrade` says
what reversing it buys: "after this runs, any SQL injection or RCE in either
service can erase the rows recording the calls it made." Since 26 September
2026 the scripts and the runner live in a third image that serves no traffic,
and the serving images hold neither.

Both controls are expressed here as rules per KIND of stage, where the kind
is derived from what a stage carries and never from what it is called. That
is deliberate: `migrate` has to be a description, not a label a stage can
wear to escape the serving rules.

WHAT THIS FILE CAN AND CANNOT ESTABLISH

It parses the Dockerfile. It therefore proves what the build is *instructed*
to do, and it proves that for every stage at once, including stages added
after this was written. It does not prove what a built image *contains*.
Those differ whenever the instructions are right and something else is wrong:
a base image that already carries the other service, a `.dockerignore` change
that alters what `COPY . .` picks up in the builder, a volume mounted over
`/app` at run time, or a registry serving a different layer under a tag.

The alembic rule is the weaker of the two here, and worth naming as such. It
checks that a serving image's virtualenv came from a stage that deletes the
entry point. It cannot see whether the deletion worked, whether the package
survived beside the script, or whether some other layer put either back.

Only running the built image settles any of that, and a build inside
`make ci` would add minutes to a gate that finishes in about 150 seconds. So
the evidence is split deliberately: the assertions below run every time, and
the image-level proof is taken by hand when the copy layer changes. It was
taken on 26 September 2026 and recorded there, on all three images:
`/app/services/confirm` absent from `api`, `/app/services/api` absent from
`confirm`, ``importlib.import_module`` raising ``ModuleNotFoundError`` for
every module of the other service in each, `command -v alembic` empty and
``import alembic`` raising in both serving images, `/app/migrations` absent
from both, and the `migrate` image running `alembic upgrade head` against a
live Postgres to land the schema at `f1860c110112`.

The cheap way to close the gap, not built here because it needs a place to
run rather than more code: the deploy workflow already builds all three
images on every dispatch, so one step per image asserting the absent thing is
absent would make it a hard gate at the only moment the images exist, without
costing `make ci` anything.
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

# The migration runner's two inputs, as copy sources.
_MIGRATION_SRCS = frozenset({"/app/migrations", "/app/migrations/", "/app/alembic.ini"})

# Copy sources that hand a stage the whole tree, and with it every service.
# `/app/services` is here for the same reason `/app` is: it is the directory
# holding all of them, so copying it copies both.
_WHOLESALE_SRCS = frozenset({".", "./", "/app", "/app/", "/app/services", "/app/services/"})

# The subset of those that also brings the migration scripts. `/app/services`
# is a wholesale copy of the services and of nothing else, so a stage doing
# only that carries no migrations and the failure should say so.
_WHOLE_TREE_SRCS = frozenset({".", "./", "/app", "/app/"})

# Where the virtualenv lands, and the console script a migration runner needs.
_VENV_DEST = "/app/.venv"
_ALEMBIC_SCRIPT = "/app/.venv/bin/alembic"

# A line continued onto the next one.
_CONTINUATION_RE = re.compile(r"\\\s*\n\s*")


@dataclass(frozen=True)
class _Copy:
    """One COPY: where it reads from, what it reads, where it lands."""

    from_stage: str | None
    sources: tuple[str, ...]
    dest: str


@dataclass(frozen=True)
class _Stage:
    """One `FROM` block: what it builds on, copies, runs and starts."""

    name: str
    base: str
    copies: tuple[_Copy, ...]
    runs: tuple[str, ...]
    cmd: str | None

    @property
    def copy_sources(self) -> tuple[str, ...]:
        """Every path this stage's own COPY instructions read."""
        return tuple(source for copy in self.copies for source in copy.sources)


def _logical_lines(text: str) -> list[str]:
    """Return the Dockerfile's instructions, joined and stripped of comments."""
    joined = _CONTINUATION_RE.sub(" ", text)
    return [
        line.strip()
        for line in joined.splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]


def _parse_copy(arguments: str) -> _Copy | None:
    """Return a COPY's origin, sources and destination."""
    from_stage = None
    operands: list[str] = []
    for token in arguments.split():
        if token.startswith("--from="):
            from_stage = token.removeprefix("--from=")
        elif not token.startswith("--"):
            operands.append(token)
    if len(operands) < 2:
        return None
    return _Copy(from_stage, tuple(operands[:-1]), operands[-1])


def _stages() -> list[_Stage]:
    """Return every named stage in the Dockerfile, in file order."""
    stages: list[_Stage] = []
    name = base = None
    copies: list[_Copy] = []
    runs: list[str] = []
    cmd: str | None = None

    def flush() -> None:
        if name is not None and base is not None:
            stages.append(_Stage(name, base, tuple(copies), tuple(runs), cmd))

    for line in _logical_lines(_DOCKERFILE.read_text()):
        verb, _, arguments = line.partition(" ")
        match = _FROM_RE.match(line)
        if match is not None:
            flush()
            name, base = match.group("name"), match.group("base")
            copies, runs, cmd = [], [], None
        elif verb.upper() == "COPY":
            parsed = _parse_copy(arguments)
            if parsed is not None:
                copies.append(parsed)
        elif verb.upper() == "RUN":
            runs.append(arguments)
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


def _carries_migrations(stage: _Stage, by_name: dict[str, _Stage]) -> bool:
    """Say whether a stage ends up holding the migration scripts."""
    return any(
        source in _MIGRATION_SRCS or source in _WHOLE_TREE_SRCS
        for member in _chain(stage, by_name)
        for source in member.copy_sources
    )


def _kind(stage: _Stage, by_name: dict[str, _Stage], all_services: set[str]) -> str:
    """Classify a shipped stage by what it carries, never by its name.

    Two kinds are recognised and a third outcome is a failure. Deriving the
    kind from the contents is what stops `migrate` becoming a label a stage
    can wear to escape the serving rules: a stage holding a service is a
    serving stage whatever it is called, and one holding both is neither.
    """
    services = _services_visible(stage, by_name, all_services)
    migrations = _carries_migrations(stage, by_name)
    if len(services) == 1 and not migrations:
        return "serving"
    if not services and migrations:
        return "migrate"
    return "unclassified"


def _venv_origin(stage: _Stage, by_name: dict[str, _Stage]) -> str | None:
    """Return the stage a stage's virtualenv was copied out of."""
    for member in _chain(stage, by_name):
        for copy in member.copies:
            if copy.dest.rstrip("/") == _VENV_DEST or _VENV_DEST in copy.sources:
                return copy.from_stage
    return None


def _strips_alembic(stage_name: str | None, by_name: dict[str, _Stage]) -> bool:
    """Say whether a stage, or one it is built on, deletes the alembic script."""
    stage = by_name.get(stage_name or "")
    if stage is None:
        return False
    return any(
        _ALEMBIC_SCRIPT in command for member in _chain(stage, by_name) for command in member.runs
    )


def _shipped_stages() -> tuple[list[_Stage], dict[str, _Stage]]:
    """Return the stages that become images, and every stage by name.

    A stage is shipped when nothing else builds on it and nothing copies out
    of it. Derived rather than listed, so a fourth target added tomorrow is
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


def test_every_shipped_image_is_a_kind_this_file_recognises() -> None:
    """Each image is either a serving image or the migration runner.

    A stage carrying no service and no migrations can start nothing and
    explains itself to nobody. A stage carrying both is the defect this file
    exists to catch wearing a second hat: it would hold a service and the
    tool that can reverse `f1860c110112`, which is the pairing that made an
    RCE in the read container able to erase its own audit rows.

    The kind comes from the contents, never from the stage's name, so
    `migrate` is a description and not an exemption anything can claim.
    """
    shipped, by_name = _shipped_stages()
    all_services = _repo_services()

    for stage in shipped:
        kind = _kind(stage, by_name, all_services)
        if kind != "unclassified":
            continue
        services = sorted(_services_visible(stage, by_name, all_services))
        migrations = _carries_migrations(stage, by_name)
        raise AssertionError(
            f"The `{stage.name}` image is neither a serving image nor a migration "
            f"runner: it carries services {services} and "
            f"{'the migration scripts' if migrations else 'no migration scripts'}. "
            "A serving image carries exactly one service and no migrations; the "
            "migration runner carries the migrations and no service. Anything "
            "else is a stage nobody can explain, and it ships."
        )


def test_each_serving_image_carries_one_service_and_runs_it() -> None:
    """A serving image holds its own service and starts that one.

    Both halves matter. The count is what keeps the read container free of
    the write path. The pairing is what the count cannot see: a stage holding
    `confirm` while running `services.api.main:app` passes any count and
    fails at startup.
    """
    shipped, by_name = _shipped_stages()
    all_services = _repo_services()
    serving = [s for s in shipped if _kind(s, by_name, all_services) == "serving"]
    assert serving, "no serving image found; the two services have to ship somehow"

    for stage in serving:
        (carried,) = _services_visible(stage, by_name, all_services)
        assert stage.cmd, f"The `{stage.name}` image declares no CMD, so it starts nothing."
        assert f"services.{carried}." in stage.cmd, (
            f"The `{stage.name}` image carries `services/{carried}` but its command "
            f"does not run it: {stage.cmd}. One of the two is wrong, and the "
            "container finds out at startup."
        )


def test_no_serving_image_can_run_a_migration() -> None:
    """A serving image holds neither the migration scripts nor the runner.

    Two halves, and the second is the one a file listing misses. Until
    26 September 2026 both serving images carried `migrations/` AND the
    `alembic` console script, which arrives inside the virtualenv rather than
    as a copied path. The api service holds `POSTERN_DATABASE_URL` because it
    needs one, so an attacker with RCE there had the scripts, the runner and
    the credential together, and `f1860c110112`'s own `downgrade` says what
    that buys: "after this runs, any SQL injection or RCE in either service
    can erase the rows recording the calls it made."

    The scripts half falls out of the kind. The runner half is asserted here:
    a serving image's virtualenv must come from a stage that deletes the
    alembic entry point, and which stage that is comes from following the
    COPY, not from a name written down here.
    """
    shipped, by_name = _shipped_stages()
    all_services = _repo_services()
    serving = [s for s in shipped if _kind(s, by_name, all_services) == "serving"]
    assert serving, "no serving image found"

    for stage in serving:
        origin = _venv_origin(stage, by_name)
        assert origin is not None, (
            f"The `{stage.name}` image copies no virtualenv, or this file could "
            "not find where it came from, so it cannot check what is in it."
        )
        assert _strips_alembic(origin, by_name), (
            f"The `{stage.name}` image takes its virtualenv from stage `{origin}`, "
            f"which never removes {_ALEMBIC_SCRIPT}. A serving container with the "
            "migration runner on its PATH and a database URL in its environment "
            "can reverse the append-only migration and then delete the rows "
            "recording what it did."
        )


def test_the_migration_runner_carries_the_scripts_and_no_service() -> None:
    """The migration image runs alembic, holds the scripts, serves nothing.

    The scripts and the runner have to live somewhere, and this is the image
    whose whole purpose is to hold them. It answers no requests, so there is
    nothing in it to reach over the network, and it is the only one of the
    three an operator should hand a database URL with DDL rights.
    """
    shipped, by_name = _shipped_stages()
    all_services = _repo_services()
    migrators = [s for s in shipped if _kind(s, by_name, all_services) == "migrate"]
    assert migrators, (
        "No migration image is shipped, so `alembic upgrade head` has nowhere to "
        "run. Removing the scripts from the serving images without giving them a "
        "home breaks the deploy rather than hardening it."
    )

    for stage in migrators:
        assert stage.cmd and "alembic" in stage.cmd, (
            f"The `{stage.name}` image carries the migration scripts but its "
            f"command does not run alembic: {stage.cmd}. An image that holds the "
            "runner and starts something else is not a migration runner."
        )
        sources = {source for member in _chain(stage, by_name) for source in member.copy_sources}
        assert "/app/alembic.ini" in sources, (
            f"The `{stage.name}` image has no `alembic.ini`, which is what "
            "resolves `script_location` to the scripts beside it."
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

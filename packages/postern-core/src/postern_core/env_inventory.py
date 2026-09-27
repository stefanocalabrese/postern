"""Every ``POSTERN_*`` variable this codebase reads, and a guard over the rest.

WHAT THIS CLOSES, and it is the one hole in the family `postern_core/config.py`
holds. Every reader in that module takes a NAME and validates the VALUE behind
it: `int_from_env` refuses ``POSTERN_CACHE_TTL_SECONDS=0``, `float_from_env`
refuses ``inf``, `bool_from_env` refuses ``POSTERN_REQUIRE_REDIS=maybe`` rather
than reading it as no. Not one of them can see ``POSTERN_REQUIRE_REDDIS=1``,
because no code asks for that name, so nothing reads the value and an unset
variable is indistinguishable from a misspelt one. The operator armed nothing
and was told nothing. `tests/test_settings_bounds.py`'s AST sweep is blind for
the same reason one level up: it polices the names the CODE reads, and a
misspelling exists only in the ENVIRONMENT.

It is worth a control rather than a documentation line because the names most
worth misspelling are the safety switches. ``POSTERN_REQUIRE_REDIS`` refuses
per-replica state, ``POSTERN_REQUIRE_PEM_KEY`` refuses an ephemeral signing key,
``POSTERN_STRICT_HEADERS`` arms MCP header validation, and this repository has
already shipped two spelling defects in that family: ``=true`` meant "off" on
all three until 2026-09-26, and ``POSTERN_REQUIRE_REDIS`` was enforced on one
of the two services until the same day. Both were about spelling. The value
half is now closed by `bool_from_env`. This is the name half.

THREE POPULATIONS, AND THE SECOND IS WHY THE THIRD CAN BE STRICT.

1. A name THIS service reads. Silent.
2. A name the OTHER service reads. Reported once, never refused.
   ``POSTERN_CONFIRM_RATE_LIMIT_TOKEN`` in `services/api`'s environment is an
   operator running one env file against two deployables, not a typo.
   ``docker-compose.yml`` gives each service its own ``environment:`` block so
   it cannot happen there, but a single ECS task definition or one Helm values
   file feeding both charts does it immediately, and refusing would make this
   guard unusable in exactly the deployments that most need it. The report is
   not merely tidy: ``POSTERN_REQUIRE_PEM_KEY`` is read by `services/api` and
   nowhere else, so an operator who sets it on the write path believes they
   refused an ephemeral WRITE key and did not.
3. A name NEITHER service reads. Refused. This is ``POSTERN_REQUIRE_REDDIS``.

WHY 3 REFUSES RATHER THAN WARNS, which is the one decision here that is not
inherited. Every other guard in this family refuses because a value it READ was
wrong; this refuses because of a variable nothing reads at all, so it is the
only guard in the repository that can stop a deployment over something with no
effect. Three things settle it. ``POSTERN_*`` is this application's namespace
and a name in it that nothing reads is either a typo or a squat, which is the
same argument `bool_from_env` already makes one level down about a value it
cannot interpret -- "the operator typed something this program cannot
interpret, and learns so at startup". A warning is what the original defect
survived behind for six days. And the failure is deterministic and
deploy-time, not a 3am surprise: the same environment refuses every time, with
the offending name, the nearest name that IS read, and a one-line fix in the
message.

`ALLOWED_UNREAD_ENV` is what makes that survivable, and it is a DECLARATION
rather than an off switch: an operator names the variables their deployment
sets for something other than Postern, one per entry, and the guard keeps
refusing everything else. An off switch would be turned on once by the first
crash loop and would then cover every future typo, which is the hole.

AND IT IS NOT ITSELF THE HOLE. A variable that relaxes a check is a
``POSTERN_*`` name someone can misspell. Misspelling this one cannot turn the
check off: the misspelling is an unread ``POSTERN_*`` name, so the guard refuses
-- and names this variable as the nearest name that is read, which is the fix.
A misspelling inside the list fails the same way, on the stray variable the
entry was meant to cover. Every path through a wrong hatch is louder than the
one it was trying to quiet, never quieter.

WHY THE INVENTORY LIVES HERE AND NOT IN THE TEST THAT POLICES IT. A runtime
guard cannot import from ``tests``, so the list had to move into production
code, and the question was whether the test keeps a second copy. It does not:
`tests/test_settings_bounds.py` imports `INVENTORY` and derives every set it
used to spell out, so the repository holds ONE copy of the name list. What
stops that copy from drifting is that the same test re-derives the same names
from the syntax tree of every shipping module and fails when the two disagree
-- in either direction, a name added here that nothing reads, or a name read
that is not here. A list that disagrees with the code it describes is the
defect this project spent a day removing from its prose; it is not being
reintroduced as data.

WHAT ``services`` MEANS, AND THE ONE IMPRECISION IN IT. A variable read under
``services/api`` is the read path's, one read under ``services/confirm`` is the
write path's, and one read under ``packages/postern-core`` is recorded as
BOTH, because both services import that library. That last is sometimes
generous: ``POSTERN_REDIS_SESSION_TTL`` is read by `postern_core.risk.session`'s
``RedisSessionStore``, which only `services/api` builds, so setting it on the
write path is recorded as read when nothing reads it. The error is always in
the direction of calling a variable read, so it can cost a report that was
owed and can never produce a refusal that was not.
"""

from __future__ import annotations

import dataclasses
import difflib
import logging
import os

__all__ = [
    "ALLOWED_UNREAD_ENV",
    "ENV_PREFIX",
    "INVENTORY",
    "KNOWN_ENV",
    "SERVICES",
    "EnvVar",
    "EnvironmentReport",
    "UnknownName",
    "classify_environment",
    "enforce_known_environment",
    "names_read_by",
]

logger = logging.getLogger(__name__)

#: The namespace this application owns, underscore included.
#:
#: The underscore is load-bearing. A prefix test of ``POSTERN`` alone would
#: claim every variable whose name merely starts with those seven letters, so a
#: ``POSTERNX_TOKEN`` belonging to something else would be refused by a guard
#: that has no business reading it.
ENV_PREFIX = "POSTERN_"

#: The two deployables. `names_read_by` refuses anything else.
SERVICES = frozenset({"api", "confirm"})

#: Where an operator declares a ``POSTERN_*`` variable this service does not read.
#:
#: Comma-separated, one exact name per entry, empty entries and surrounding
#: whitespace ignored. No wildcards: a ``POSTERN_SIDECAR_*`` entry would let a
#: typo inside that family through in silence, which is the defect the guard
#: exists for.
ALLOWED_UNREAD_ENV = "POSTERN_ALLOWED_UNREAD_ENV"


@dataclasses.dataclass(frozen=True)
class EnvVar:
    """One variable, what kind of value it holds, and which services read it.

    ``kind`` is ``"string"``, ``"number"`` or ``"flag"``, and it is here rather
    than only in the test because it is what makes the test's three sets
    derivable from this one table instead of re-listed beside it. The guard
    itself never reads it.
    """

    name: str
    kind: str
    services: tuple[str, ...]


#: Read by both deployables. Spelled once so the table below stays readable.
BOTH = ("api", "confirm")

#: Every ``POSTERN_*`` variable any shipping module reads.
#:
#: Generated from the syntax tree on 2026-09-27 rather than typed, and pinned
#: against it by `tests/test_settings_bounds.py` on every run. 56 rows: 18
#: strings, 34 numbers, 3 flags, and this guard's own declaration variable.
INVENTORY: tuple[EnvVar, ...] = (
    EnvVar(ALLOWED_UNREAD_ENV, "string", BOTH),
    EnvVar("POSTERN_APP_ASSERTION_AUDIENCE", "string", ("confirm",)),
    EnvVar("POSTERN_APP_ASSERTION_ISSUER", "string", ("confirm",)),
    EnvVar("POSTERN_APP_ASSERTION_JWKS_URI", "string", ("confirm",)),
    EnvVar("POSTERN_AUDIENCE", "string", ("api",)),
    EnvVar("POSTERN_BACKEND_BASE_URL", "string", BOTH),
    EnvVar("POSTERN_BACKEND_CONNECT_TIMEOUT_SECONDS", "number", ("api",)),
    EnvVar("POSTERN_BACKEND_POOL_TIMEOUT_SECONDS", "number", ("api",)),
    EnvVar("POSTERN_BACKEND_READ_TIMEOUT_SECONDS", "number", ("api",)),
    EnvVar("POSTERN_BACKEND_WRITE_TIMEOUT_SECONDS", "number", ("api",)),
    EnvVar("POSTERN_CACHE_TTL_SECONDS", "number", ("api",)),
    EnvVar("POSTERN_CONFIRM_CUSTOMER_RATE_LIMIT_APPROVE", "number", ("confirm",)),
    EnvVar("POSTERN_CONFIRM_CUSTOMER_RATE_LIMIT_CHALLENGE_APPROVE", "number", ("confirm",)),
    EnvVar("POSTERN_CONFIRM_DATABASE_AUDIT_RESERVE_SIZE", "number", ("confirm",)),
    EnvVar("POSTERN_CONFIRM_DATABASE_MAX_OVERFLOW", "number", ("confirm",)),
    EnvVar("POSTERN_CONFIRM_DATABASE_POOL_SIZE", "number", ("confirm",)),
    EnvVar("POSTERN_CONFIRM_MAX_BODY_BYTES", "number", ("confirm",)),
    EnvVar("POSTERN_CONFIRM_RATE_LIMIT_APPROVE", "number", ("confirm",)),
    EnvVar("POSTERN_CONFIRM_RATE_LIMIT_CHALLENGE_APPROVE", "number", ("confirm",)),
    EnvVar("POSTERN_CONFIRM_RATE_LIMIT_DEFAULT", "number", ("confirm",)),
    EnvVar("POSTERN_CONFIRM_RATE_LIMIT_DEVICE_AUTHORIZATION", "number", ("confirm",)),
    EnvVar("POSTERN_CONFIRM_RATE_LIMIT_TOKEN", "number", ("confirm",)),
    EnvVar("POSTERN_CONFIRM_TRUSTED_PROXY_HOPS", "number", ("confirm",)),
    EnvVar("POSTERN_DATABASE_AUDIT_RESERVE_SIZE", "number", ("api",)),
    EnvVar("POSTERN_DATABASE_COMMAND_TIMEOUT_SECONDS", "number", BOTH),
    EnvVar("POSTERN_DATABASE_CONNECT_TIMEOUT_SECONDS", "number", BOTH),
    EnvVar("POSTERN_DATABASE_MAX_OVERFLOW", "number", ("api",)),
    EnvVar("POSTERN_DATABASE_POOL_SIZE", "number", ("api",)),
    EnvVar("POSTERN_DATABASE_POOL_TIMEOUT_SECONDS", "number", BOTH),
    EnvVar("POSTERN_DATABASE_URL", "string", BOTH),
    EnvVar("POSTERN_DEVICE_CODE_TTL_SECONDS", "number", ("confirm",)),
    EnvVar("POSTERN_DEVICE_KEYS_PATH", "string", ("confirm",)),
    EnvVar("POSTERN_DEVICE_POLL_INTERVAL_SECONDS", "number", ("confirm",)),
    EnvVar("POSTERN_DEVICE_VERIFICATION_URI", "string", ("confirm",)),
    EnvVar("POSTERN_JWKS_URI", "string", ("api",)),
    EnvVar("POSTERN_MAX_BODY_BYTES", "number", ("api",)),
    EnvVar("POSTERN_MAX_CLIENT_ID_LENGTH", "number", ("confirm",)),
    EnvVar("POSTERN_MAX_DEVICE_CODES", "number", ("confirm",)),
    EnvVar("POSTERN_MAX_SCOPES_LENGTH", "number", ("confirm",)),
    EnvVar("POSTERN_READ_KEY_KID", "string", BOTH),
    EnvVar("POSTERN_READ_KEY_PEM_PATH", "string", BOTH),
    EnvVar("POSTERN_READ_TOKEN_ISSUER", "string", BOTH),
    EnvVar("POSTERN_REDIS_DEVICE_CODE_TTL", "number", BOTH),
    EnvVar("POSTERN_REDIS_KEY_PREFIX", "string", BOTH),
    EnvVar("POSTERN_REDIS_SESSION_TTL", "number", BOTH),
    EnvVar("POSTERN_REDIS_URL", "string", BOTH),
    EnvVar("POSTERN_REQUEST_DEADLINE_SECONDS", "number", ("api",)),
    EnvVar("POSTERN_REQUIRE_PEM_KEY", "flag", ("api",)),
    EnvVar("POSTERN_REQUIRE_REDIS", "flag", BOTH),
    EnvVar("POSTERN_STRICT_HEADERS", "flag", ("api",)),
    EnvVar("POSTERN_TOKEN_ISSUER", "string", ("api",)),
    EnvVar("POSTERN_TRUSTED_PROXY_HOPS", "number", ("api",)),
    EnvVar("POSTERN_USER_CODE_MAX_ATTEMPTS", "number", ("confirm",)),
    EnvVar("POSTERN_WRITE_KEY_KID", "string", ("confirm",)),
    EnvVar("POSTERN_WRITE_KEY_PEM_PATH", "string", ("confirm",)),
    EnvVar("POSTERN_WRITE_TOKEN_ISSUER", "string", ("confirm",)),
)

#: Every name the codebase reads, whichever service reads it.
#:
#: This, and not the per-service set, is the pool a typo is matched against: an
#: operator misspelling a write-path variable while deploying the read path has
#: made the same mistake and is owed the same answer.
KNOWN_ENV: frozenset[str] = frozenset(entry.name for entry in INVENTORY)


def names_read_by(service: str) -> frozenset[str]:
    """The names ``service`` reads.

    Raises:
        ValueError: if ``service`` is not one of `SERVICES`. A caller naming a
            third deployable would otherwise get an empty set, and an empty set
            makes every variable in the environment unread -- a guard that
            refuses everything, from a typo in an argument no operator can
            reach.
    """
    if service not in SERVICES:
        raise ValueError(f"{service!r} is not one of {sorted(SERVICES)}")
    return frozenset(entry.name for entry in INVENTORY if service in entry.services)


@dataclasses.dataclass(frozen=True)
class UnknownName:
    """A ``POSTERN_*`` variable nothing reads, and the nearest name that is read.

    ``suggestion`` is ``None`` when nothing is close enough. A wrong guess sends
    an operator to edit a line that was right, so silence is the better answer.
    """

    name: str
    suggestion: str | None


@dataclasses.dataclass(frozen=True)
class EnvironmentReport:
    """The three populations, plus what the operator declared.

    ``unknown`` is what `enforce_known_environment` raises on, ``unread`` is
    what it logs, ``declared`` is what `ALLOWED_UNREAD_ENV` accounted for, and
    a name this service reads appears in none of them.
    """

    unknown: tuple[UnknownName, ...]
    unread: tuple[str, ...]
    declared: tuple[str, ...]


def _declared_names(environ: dict[str, str]) -> frozenset[str]:
    raw = environ.get(ALLOWED_UNREAD_ENV) or ""
    return frozenset(entry.strip() for entry in raw.split(",") if entry.strip())


def _nearest(name: str) -> str | None:
    """The closest name in `KNOWN_ENV`, or ``None`` when none is close.

    ``difflib`` rather than a hand-written edit distance: it is in the standard
    library, and the cutoff is a ratio rather than a character count so a typo
    in a long name is judged as leniently as one in a short name.

    The candidate is looked up under the name as typed AND under its stripped,
    upper-cased form, which is what catches ``postern_require_redis``: the
    variable is a different one from ``POSTERN_REQUIRE_REDIS`` on every
    platform this ships to, and the operator who wrote it does not think so.
    """
    for candidate in (name, name.strip().upper()):
        if candidate in KNOWN_ENV:
            return candidate
        close = difflib.get_close_matches(candidate, sorted(KNOWN_ENV), n=1, cutoff=0.8)
        if close:
            return close[0]
    return None


def classify_environment(service: str, environ: dict[str, str] | None = None) -> EnvironmentReport:
    """Sort a deployment's ``POSTERN_*`` variables into the three populations.

    Args:
        service: Which deployable is asking. One of `SERVICES`.
        environ: The environment to read. Defaults to the process's own. It is
            a parameter so the classification can be tested and reasoned about
            without mutating global state, and so a caller can ask what a
            DIFFERENT deployment's environment would do.

    Returns:
        An `EnvironmentReport`. It raises nothing: a pure function over a
        mapping, so `enforce_known_environment` below owns the whole decision
        about what is fatal and what is logged, in one place a reader can find.

    A variable whose name is outside `ENV_PREFIX` is not looked at, which is the
    scoping that keeps this from being a guard over an operator's whole
    environment. ``PATH`` is not ours to have an opinion about.
    """
    names_read_by(service)  # rejects an unknown service before anything else
    environment = os.environ if environ is None else environ
    mine = names_read_by(service)
    declared = _declared_names(dict(environment))

    unknown: list[UnknownName] = []
    unread: list[str] = []
    accounted: list[str] = []
    for name in sorted(environment):
        if not name.strip().upper().startswith(ENV_PREFIX):
            continue
        if name in mine:
            continue
        if name in KNOWN_ENV:
            unread.append(name)
            continue
        if name in declared:
            accounted.append(name)
            continue
        unknown.append(UnknownName(name, _nearest(name)))
    return EnvironmentReport(tuple(unknown), tuple(unread), tuple(accounted))


def enforce_known_environment(*, service: str) -> None:
    """Refuse to start when a ``POSTERN_*`` variable is set that nothing reads.

    Args:
        service: Which deployable is starting. One of `SERVICES`. Keyword-only,
            matching `postern_core.config`'s `enforce_redis_requirement`, whose
            shape this follows: one implementation in the library both services
            import, called from each composition root, parameterised by the one
            thing that differs between them.

    Raises:
        RuntimeError: if any ``POSTERN_*`` variable is set that neither service
            reads and that `ALLOWED_UNREAD_ENV` does not declare. `RuntimeError`
            and not `ValueError` for the reason `enforce_redis_requirement`
            gives: a `ValueError` in this family says a value this service needs
            is malformed, and this says a deployment-wide contract about the
            ``POSTERN_*`` namespace was not met.
        ValueError: if ``service`` is not one of `SERVICES`, which is a
            programming error in a composition root rather than anything an
            operator can cause.

    A variable the OTHER service reads is logged at warning level, once, however
    many there are: a line per variable on a shared env file is a log nobody
    reads, and the whole point of the line is that somebody does.
    """
    report = classify_environment(service)
    if report.unread:
        logger.warning(
            "%s set that this service (%s) does not read, and configure nothing here: "
            "%s. That is expected when one environment file serves both deployables. It "
            "is worth checking when the variable is a safety switch: "
            "POSTERN_REQUIRE_PEM_KEY and POSTERN_STRICT_HEADERS are read by the api "
            "service only, so setting either on the confirm service arms nothing.",
            "1 POSTERN_ variable is"
            if len(report.unread) == 1
            else f"{len(report.unread)} POSTERN_ variables are",
            service,
            ", ".join(report.unread),
        )
    if not report.unknown:
        return
    lines = []
    for unknown in report.unknown:
        if unknown.suggestion == unknown.name.strip().upper():
            hint = (
                f"Did you mean {unknown.suggestion}? Variable names are matched byte "
                f"for byte, so case and surrounding spaces make a different variable."
            )
        elif unknown.suggestion:
            hint = f"Did you mean {unknown.suggestion}?"
        else:
            hint = "No name this codebase reads is close to it."
        lines.append(f"  {unknown.name} -- {hint}")
    count = len(report.unknown)
    subject = "1 POSTERN_ variable is" if count == 1 else f"{count} POSTERN_ variables are"
    raise RuntimeError(
        f"{subject} set that no code in this deployment reads:\n" + "\n".join(lines) + "\n"
        "A variable this application does not read arms no control, and an unread name "
        "is indistinguishable from one that was never set -- which is how "
        "POSTERN_REQUIRE_PEM_KEY=true came to mean 'do not require a PEM key'. Fix the "
        f"spelling, or list the name in {ALLOWED_UNREAD_ENV} (comma-separated, exact "
        "names, no wildcards) if this deployment sets it for something other than "
        "Postern. The value behind it is not shown here and is not read anywhere."
    )

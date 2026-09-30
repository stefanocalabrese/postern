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

THE MIRROR, ADDED 2026-09-28: a variable that is ABSENT and needed. Everything
above fires on a name that is present and wrong. Nothing fired on one that was
missing, because for all three flags "absent" and "deliberately off" are the
same state, so the control an operator believed they had armed was simply not
armed and nothing said so. `REQUIRED_ENV` is where a deployment declares which
variables it must provide, and its own docstring carries what that can and
cannot reach -- the short version is that a total environment loss is already
fatal on both services, so what this closes is one key dropped or renamed.

The two halves are one guard and one refusal, not two checks in sequence,
because they are usually one mistake seen from two angles: a renamed key is
simultaneously a name nothing reads and a requirement nothing meets. They also
cover each other. A typo in the requirement list is caught whether or not the
misspelt variable is also set -- set, and the namespace half refuses it; unset,
and the namespace half cannot see it at all while the requirement half refuses
the unsatisfiable entry.

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
from collections.abc import Mapping

__all__ = [
    "ALLOWED_UNREAD_ENV",
    "ENV_PREFIX",
    "REQUIRED_ENV",
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

#: Everything that runs this repository's code and reads its environment.
#:
#: ``migrations`` joined the two services on 2026-09-28 and is not a deployable
#: in the same sense: it is ``alembic upgrade``, a one-off task in its own image
#: with a role holding DDL rights. It is here because it reads
#: ``POSTERN_DATABASE_URL`` and because what a misspelling of that name does
#: there is worse than anything the two services can suffer -- `migrations/env.py`
#: falls back to ``alembic.ini``'s ``sqlalchemy.url``, so the migration runs
#: against whatever THAT names.
SERVICES = frozenset({"api", "confirm", "migrations"})

#: Where an operator declares a ``POSTERN_*`` variable this service does not read.
#:
#: Comma-separated, one exact name per entry, empty entries and surrounding
#: whitespace ignored. No wildcards: a ``POSTERN_SIDECAR_*`` entry would let a
#: typo inside that family through in silence, which is the defect the guard
#: exists for.
ALLOWED_UNREAD_ENV = "POSTERN_ALLOWED_UNREAD_ENV"

#: Where an operator declares the variables this deployment MUST provide.
#:
#: The mirror of `ALLOWED_UNREAD_ENV` and deliberately the same format: comma
#: separated, one exact name per entry, empty entries and surrounding whitespace
#: ignored, no wildcards. Two lists that mean opposite things are easier to hold
#: in one head when they are read the same way.
#:
#: WHAT IT CANNOT DO, said here because it is the first thing to understand about
#: it: if the whole environment is lost, this is lost with it, no requirement is
#: declared, and nothing is checked. A list that lives in the environment cannot
#: guard the environment's own existence. What makes that acceptable rather than
#: fatal to the idea is that a total loss is ALREADY loud -- measured with every
#: ``POSTERN_`` variable deleted, `services/api`'s `Settings.from_env` raises
#: ``KeyError: 'POSTERN_BACKEND_BASE_URL'`` and `create_confirm_app` raises
#: `ValueError` naming the three assertion settings. Neither service starts.
#:
#: So the population this closes is ONE key dropped or renamed on a variable
#: that has a default, which is every remaining case in which a deployment
#: starts weaker than its operator believes: ``POSTERN_REQUIRE_REDIS`` gone means
#: per-replica state accepted, ``POSTERN_REQUIRE_PEM_KEY`` gone means an
#: ephemeral signing key accepted, ``POSTERN_REDIS_URL`` gone means four stores
#: in memory, ``POSTERN_JWKS_URI`` gone means the read path serving with no
#: customer authentication.
REQUIRED_ENV = "POSTERN_REQUIRED_ENV"


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


#: Read by both services. Spelled once so the table below stays readable.
BOTH = ("api", "confirm")

#: Read wherever the guard runs, which is everything in `SERVICES`.
#:
#: Only this module's own two variables carry it, and that is not an exception to
#: the attribution rule but an instance of it: they are read by
#: `classify_environment`, every caller of the guard reaches that read, and
#: ``alembic upgrade`` is now one of those callers.
EVERYWHERE = ("api", "confirm", "migrations")

#: Every ``POSTERN_*`` variable any shipping module reads.
#:
#: Generated from the syntax tree on 2026-09-27 rather than typed, and pinned
#: against it by `tests/test_settings_bounds.py` on every run. 74 rows since
#: 2026-09-30: 27 strings (25 settings plus this guard's own two lists), 44
#: numbers, 3 flags. The eight ``POSTERN_VAULT_*`` rows below the device-code
#: block arrived on 2026-09-29; ``POSTERN_DEVICE_APP_LINK_URI`` and the seven
#: QR-page rate limits arrived on 2026-09-30, the day
#: ``POSTERN_USER_CODE_MAX_ATTEMPTS`` left with the attempt budget it set, and
#: ``POSTERN_CONFIRM_ASSERTION_MAX_LIFETIME_SECONDS`` arrived later that day,
#: and ``POSTERN_CONFIRM_PAIRING_ENRICHER_TIMEOUT_SECONDS`` after it.
INVENTORY: tuple[EnvVar, ...] = (
    EnvVar(ALLOWED_UNREAD_ENV, "string", EVERYWHERE),
    EnvVar(REQUIRED_ENV, "string", EVERYWHERE),
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
    EnvVar("POSTERN_CONFIRM_ASSERTION_MAX_LIFETIME_SECONDS", "number", ("confirm",)),
    EnvVar("POSTERN_CONFIRM_CUSTOMER_RATE_LIMIT_APPROVE", "number", ("confirm",)),
    EnvVar("POSTERN_CONFIRM_CUSTOMER_RATE_LIMIT_CHALLENGE_APPROVE", "number", ("confirm",)),
    EnvVar("POSTERN_CONFIRM_CUSTOMER_RATE_LIMIT_SCAN", "number", ("confirm",)),
    EnvVar("POSTERN_CONFIRM_DATABASE_AUDIT_RESERVE_SIZE", "number", ("confirm",)),
    EnvVar("POSTERN_CONFIRM_DATABASE_MAX_OVERFLOW", "number", ("confirm",)),
    EnvVar("POSTERN_CONFIRM_DATABASE_POOL_SIZE", "number", ("confirm",)),
    EnvVar("POSTERN_CONFIRM_MAX_BODY_BYTES", "number", ("confirm",)),
    EnvVar("POSTERN_CONFIRM_PAIRING_ENRICHER_TIMEOUT_SECONDS", "number", ("confirm",)),
    EnvVar("POSTERN_CONFIRM_RATE_LIMIT_APPROVE", "number", ("confirm",)),
    EnvVar("POSTERN_CONFIRM_RATE_LIMIT_CHALLENGE_APPROVE", "number", ("confirm",)),
    EnvVar("POSTERN_CONFIRM_RATE_LIMIT_DEFAULT", "number", ("confirm",)),
    EnvVar("POSTERN_CONFIRM_RATE_LIMIT_DEVICE_AUTHORIZATION", "number", ("confirm",)),
    EnvVar("POSTERN_CONFIRM_RATE_LIMIT_SCAN", "number", ("confirm",)),
    EnvVar("POSTERN_CONFIRM_RATE_LIMIT_TOKEN", "number", ("confirm",)),
    EnvVar("POSTERN_CONFIRM_RATE_LIMIT_VERIFY", "number", ("confirm",)),
    EnvVar("POSTERN_CONFIRM_RATE_LIMIT_VERIFY_CSS", "number", ("confirm",)),
    EnvVar("POSTERN_CONFIRM_RATE_LIMIT_VERIFY_JS", "number", ("confirm",)),
    EnvVar("POSTERN_CONFIRM_RATE_LIMIT_VERIFY_QR", "number", ("confirm",)),
    EnvVar("POSTERN_CONFIRM_RATE_LIMIT_VERIFY_STATE", "number", ("confirm",)),
    EnvVar("POSTERN_CONFIRM_TRUSTED_PROXY_HOPS", "number", ("confirm",)),
    EnvVar("POSTERN_DATABASE_AUDIT_RESERVE_SIZE", "number", ("api",)),
    EnvVar("POSTERN_DATABASE_COMMAND_TIMEOUT_SECONDS", "number", BOTH),
    EnvVar("POSTERN_DATABASE_CONNECT_TIMEOUT_SECONDS", "number", BOTH),
    EnvVar("POSTERN_DATABASE_MAX_OVERFLOW", "number", ("api",)),
    EnvVar("POSTERN_DATABASE_POOL_SIZE", "number", ("api",)),
    EnvVar("POSTERN_DATABASE_POOL_TIMEOUT_SECONDS", "number", BOTH),
    EnvVar("POSTERN_DATABASE_URL", "string", EVERYWHERE),
    EnvVar("POSTERN_DEVICE_APP_LINK_URI", "string", ("confirm",)),
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
    # THE VAULT FAMILY, added 2026-09-29 with transit signing. Six are about
    # the Vault and are read once, in `postern_core.auth.vault.vault_from_env`,
    # so both services get identical parsing and both are recorded as reading
    # them. The two KEY NAMES are read in each service's own `from_env`, and
    # their attribution here is the read/write split written down: the write
    # key's name is read by `confirm` and by nothing else, so setting
    # POSTERN_VAULT_WRITE_KEY_NAME on the read path is reported as a variable
    # that service does not read -- which is the correct answer, because a
    # process that cannot name the write key also holds no policy to sign with
    # it.
    EnvVar("POSTERN_VAULT_ADDR", "string", BOTH),
    EnvVar("POSTERN_VAULT_PUBLIC_KEY_TTL_SECONDS", "number", BOTH),
    EnvVar("POSTERN_VAULT_READ_KEY_NAME", "string", BOTH),
    EnvVar("POSTERN_VAULT_TIMEOUT_SECONDS", "number", BOTH),
    EnvVar("POSTERN_VAULT_TOKEN", "string", BOTH),
    EnvVar("POSTERN_VAULT_TOKEN_PATH", "string", BOTH),
    EnvVar("POSTERN_VAULT_TRANSIT_MOUNT", "string", BOTH),
    EnvVar("POSTERN_VAULT_WRITE_KEY_NAME", "string", ("confirm",)),
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
    """What is set and should not be, and what should be set and is not.

    THE FIRST THREE FIELDS ARE THE NAMESPACE HALF. ``unknown`` is a variable set
    that nothing reads and is fatal; ``unread`` is one the OTHER service reads
    and is logged; ``declared`` is one `ALLOWED_UNREAD_ENV` accounted for.

    THE LAST FOUR ARE THE REQUIREMENT HALF, from `REQUIRED_ENV`. ``absent`` is
    required and not set at all; ``blank`` is required and set to nothing, which
    is a different sentence to put in front of an operator because something
    rendered that empty value; ``unsatisfiable`` is a requirement naming a
    variable no code reads, so no value could ever meet it; ``unenforceable`` is
    a requirement this service cannot check because another deployable is what
    reads it. The first three of those are fatal and the last is logged.

    A variable this service reads, set to a value, appears in none of the seven.
    """

    unknown: tuple[UnknownName, ...]
    unread: tuple[str, ...]
    declared: tuple[str, ...]
    absent: tuple[str, ...] = ()
    blank: tuple[str, ...] = ()
    unsatisfiable: tuple[UnknownName, ...] = ()
    unenforceable: tuple[str, ...] = ()


def _split_names(raw: str | None) -> frozenset[str]:
    """The names in one comma-separated list variable's VALUE.

    Shared by `ALLOWED_UNREAD_ENV` and `REQUIRED_ENV` so the two cannot drift
    into two formats. Empty entries and surrounding whitespace are dropped, which
    is what a templated list with a missing element leaves behind.

    IT TAKES THE VALUE AND NOT THE NAME, which is a deliberate shape rather than
    a preference. A helper that took the name would read the environment under a
    name the syntax tree cannot resolve, and
    `tests/test_settings_bounds.py`'s sweep would then see this module reading
    something it cannot identify -- correctly, since that is exactly how a
    variable goes missing from an inventory. Keeping the read at the call site,
    where the constant is written out, keeps both names visible to it.
    """
    return frozenset(entry.strip() for entry in (raw or "").split(",") if entry.strip())


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


def classify_environment(
    service: str, override: Mapping[str, str] | None = None
) -> EnvironmentReport:
    """Sort a deployment's ``POSTERN_*`` variables into the populations above.

    Args:
        service: Which deployable is asking. One of `SERVICES`.
        override: The environment to read instead of the process's own. It is
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
    mine = names_read_by(service)
    # THE LOCAL IS NAMED ``environ`` ON PURPOSE AND RENAMING IT LOSES A CHECK.
    # `tests/test_settings_bounds.py`'s sweep recognises an environment read by
    # the accessor's name, so ``environ.get(...)`` below is a read it can see,
    # carrying a module constant it can resolve. Spelled any other way, this
    # module's own two list variables would vanish from the inventory this module
    # is checked against, and the set-equality test would then fail in the
    # direction that says they are declared and read nowhere. The parameter is
    # ``override`` rather than ``environ`` so that this local is the only thing
    # by that name. It is pinned by
    # `tests/test_settings_bounds.py`'s attribution test, not hoped for.
    environ: Mapping[str, str] = os.environ if override is None else override
    snapshot = dict(environ)
    declared = _split_names(environ.get(ALLOWED_UNREAD_ENV))
    required = _split_names(environ.get(REQUIRED_ENV))

    unknown: list[UnknownName] = []
    unread: list[str] = []
    accounted: list[str] = []
    for name in sorted(environ):
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

    absent: list[str] = []
    blank: list[str] = []
    unsatisfiable: list[UnknownName] = []
    unenforceable: list[str] = []
    for name in sorted(required):
        if name not in KNOWN_ENV:
            unsatisfiable.append(UnknownName(name, _nearest(name)))
        elif name not in mine:
            unenforceable.append(name)
        elif name not in snapshot:
            absent.append(name)
        elif not snapshot[name].strip():
            blank.append(name)
    return EnvironmentReport(
        tuple(unknown),
        tuple(unread),
        tuple(accounted),
        tuple(absent),
        tuple(blank),
        tuple(unsatisfiable),
        tuple(unenforceable),
    )


def _hint_for(unknown: UnknownName) -> str:
    """The sentence that follows a name the guard could not place."""
    if unknown.suggestion == unknown.name.strip().upper():
        return (
            f"Did you mean {unknown.suggestion}? Variable names are matched byte for "
            f"byte, so case and surrounding spaces make a different variable."
        )
    if unknown.suggestion:
        return f"Did you mean {unknown.suggestion}?"
    return "No name this codebase reads is close to it."


def _count(names: tuple[str, ...] | tuple[UnknownName, ...]) -> str:
    """ "1 POSTERN_ variable" or "3 POSTERN_ variables"."""
    return "1 POSTERN_ variable" if len(names) == 1 else f"{len(names)} POSTERN_ variables"


def _is_are(names: tuple[str, ...] | tuple[UnknownName, ...]) -> str:
    return "is" if len(names) == 1 else "are"


def enforce_known_environment(*, service: str) -> None:
    """Refuse to start on a variable set that nothing reads, or missing and required.

    Args:
        service: Which deployable is starting. One of `SERVICES`. Keyword-only,
            matching `postern_core.config`'s `enforce_redis_requirement`, whose
            shape this follows: one implementation in the library every caller
            imports, called from each composition root, parameterised by the one
            thing that differs between them.

    Raises:
        RuntimeError: on any of four findings -- a ``POSTERN_*`` variable set
            that no code reads and `ALLOWED_UNREAD_ENV` does not declare; a
            `REQUIRED_ENV` entry this service reads and nothing set; one set to
            an empty value; or one naming a variable no code reads at all.
            `RuntimeError` and not `ValueError` for the reason
            `enforce_redis_requirement` gives: a `ValueError` in this family says
            a value this service needs is malformed, and this says a
            deployment-wide contract about the ``POSTERN_*`` namespace was not
            met.
        ValueError: if ``service`` is not one of `SERVICES`, which is a
            programming error in a composition root rather than anything an
            operator can cause.

    ONE REFUSAL FOR ALL FOUR, not four guards in sequence. An operator fixing one
    class of finding per deploy pays one deploy per class, and the four are
    usually one mistake seen from different angles: a renamed key is
    simultaneously a name nothing reads and a requirement nothing meets.

    Two findings are logged at warning level rather than raised, both because
    another deployable is the thing that reads the variable and refusing would
    crash a correct deployment that runs one environment file against two
    images. One line each however many names, because a line per variable on a
    shared env file is a log nobody reads.
    """
    report = classify_environment(service)
    if report.unread:
        logger.warning(
            "%s set that this service (%s) does not read, and configure nothing here: "
            "%s. That is expected when one environment file serves both deployables. It "
            "is worth checking when the variable is a safety switch: "
            "POSTERN_REQUIRE_PEM_KEY and POSTERN_STRICT_HEADERS are read by the api "
            "service only, so setting either on the confirm service arms nothing.",
            f"{_count(report.unread)} {_is_are(report.unread)}",
            service,
            ", ".join(report.unread),
        )
    if report.unenforceable:
        logger.warning(
            "%s in %s that this service (%s) does not read, so nothing here can check "
            "%s: %s. Another deployable reads them and will. Write one requirement list "
            "per service if you want a dropped key caught by whichever image starts.",
            _count(report.unenforceable),
            REQUIRED_ENV,
            service,
            "it" if len(report.unenforceable) == 1 else "them",
            ", ".join(report.unenforceable),
        )

    sections: list[str] = []
    if report.unknown:
        lines = "\n".join(f"  {u.name} -- {_hint_for(u)}" for u in report.unknown)
        sections.append(
            f"{_count(report.unknown)} {_is_are(report.unknown)} set that no code in "
            f"this deployment reads:\n{lines}\n"
            "A variable this application does not read arms no control, and an unread "
            "name is indistinguishable from one that was never set -- which is how "
            "POSTERN_REQUIRE_PEM_KEY=true came to mean 'do not require a PEM key'. Fix "
            f"the spelling, or list the name in {ALLOWED_UNREAD_ENV} (comma-separated, "
            "exact names, no wildcards) if this deployment sets it for something other "
            "than Postern. The value behind it is not shown here and is not read "
            "anywhere."
        )
    if report.absent:
        lines = "\n".join(f"  {name}" for name in report.absent)
        sections.append(
            f"{_count(report.absent)} named in {REQUIRED_ENV} that nothing set:\n"
            f"{lines}\n"
            "Any of these that has a default would otherwise have been taken at that "
            "default, and the process would have started and served -- which for a "
            "safety switch means the control is off while you believe it is on. Set the "
            f"variable, or remove the name from {REQUIRED_ENV} if this deployment does "
            "not need it."
        )
    if report.blank:
        lines = "\n".join(f"  {name}" for name in report.blank)
        sections.append(
            f"{_count(report.blank)} named in {REQUIRED_ENV} that something set to an "
            f"empty value:\n{lines}\n"
            "This is not the same as unset and the difference is the diagnosis: a "
            "template rendered here and produced nothing, so look at what feeds it "
            "rather than at whether the key exists. An empty value is how this "
            "repository spells 'unset' everywhere -- every reader takes its default for "
            "one -- so it cannot satisfy a requirement."
        )
    if report.unsatisfiable:
        lines = "\n".join(f"  {u.name} -- {_hint_for(u)}" for u in report.unsatisfiable)
        sections.append(
            f"{_count(report.unsatisfiable)} named in {REQUIRED_ENV} that no code in "
            f"this deployment reads:\n{lines}\n"
            "No value could satisfy this requirement, because nothing would read it. "
            "That makes it a typo in the list rather than a missing variable, and it is "
            "worth more than it looks: a misspelt name in this list is caught here even "
            "when the variable itself is unset, which is exactly when the namespace "
            "check above cannot see it."
        )
    if not sections:
        return
    raise RuntimeError("\n\n".join(sections))

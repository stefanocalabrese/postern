# 0017. A `POSTERN_` variable nothing reads stops the service from starting

Date: 27 September 2026

## Status

Accepted. `enforce_known_environment` runs first in both composition roots.

## Context

Every guard in the settings family reads a variable and validates its VALUE.
`int_from_env` refuses an unparseable number, `bool_from_env` refuses an
unrecognised flag, and the AST sweep in `tests/test_settings_bounds.py` refuses
a read that bypasses either. All of them are defeated by a misspelt NAME:
`POSTERN_REQUIRE_REDDIS=1` sets no guard and nothing notices, because an unset
variable is indistinguishable from one that was never meant to be set.

This is not hypothetical in this repository. `POSTERN_REQUIRE_PEM_KEY=true`
meant "do not require a PEM key" for six days, and that was a wrong VALUE,
which is the easier case. A wrong name has no reader to complain.

## Decision

`postern_core/env_inventory.py` holds `INVENTORY`, 56 `EnvVar(name, kind,
services)` rows, and sorts a deployment's `POSTERN_*` variables into three
populations at startup.

**This service reads it** -- silent.

**The other service reads it** -- logged once at WARNING, never fatal. One
environment file against two deployables is a deployment, not a typo.
`docker-compose.yml` gives each service its own `environment:` block; a single
ECS task definition or one Helm values file does not. Refusing this would make
the control unusable in exactly the deployments that most need it. The warning
names the case that matters: `POSTERN_REQUIRE_PEM_KEY` and
`POSTERN_STRICT_HEADERS` are read by `services/api` alone, so an operator who
sets either on the write path believes they refused an ephemeral write key or
armed header validation there, and has done neither.

**Neither reads it** -- refused, naming every offending variable and the nearest
name that IS read, from `difflib.get_close_matches` at a 0.8 ratio, with no
suggestion when nothing is close because a wrong guess sends an operator to
edit a line that was right.

### Refuse rather than warn

This is the only guard here that can stop a deployment over a variable with no
effect, so the choice was argued rather than inherited.

`POSTERN_*` is this application's namespace, and a name in it that nothing reads
is a typo or a squat. That is the argument `bool_from_env` already makes one
level down about a value it cannot interpret.

And a warning is precisely what the original defect survived behind. The
failure mode of warn-only is documented in this repository's own history.

The crash-loop objection is real, and the hatch answers it rather than
weakening the strictness: the failure is deterministic, deploy-time, and
carries its own fix in the message. Verified against what exists:
`docker-compose.yml` sets ten names and all ten are read; the Dockerfile, both
workflows, the Makefile and `alembic.ini` set none that are not.

### The hatch is a declaration, not an off switch

`POSTERN_ALLOWED_UNREAD_ENV` takes exact names, comma separated, no wildcards. A
boolean would be set once by the first crash loop and would then cover every
future typo. A wildcard would hide a typo inside the family it names.

Every path through a wrong hatch is louder than the one it was quieting.
Misspell the hatch and the misspelling is itself an unread `POSTERN_*` name, so
the guard refuses AND names the hatch as the nearest name that is read -- which
is the fix. Misspell a name inside the list and the entry matches nothing, so
the stray variable is still refused and still named.

### One list, not two

The name list lives in production code and the test derives from it.
`tests/test_settings_bounds.py`'s own `READ_AS_STRING` and `FLAGS` literals were
deleted and are now projections of `INVENTORY`.

A second list verified against the tree was the alternative and was rejected:
two lists that agree today is the state every drifted document in this
repository was once in. Drift is prevented by set equality between three
independent derivations -- the AST sweep's direct reads, its reads through a
bounded reader, and `INVENTORY` -- which fails in both directions. A name read
but not declared would make the guard refuse a variable an operator is right to
set; a name declared but read nowhere would make it accept one that arms
nothing, which is this defect reintroduced inside the control.

The value behind an unknown name is never echoed. The numeric readers echo
values because they are the operator's own environment; this guard fires on
names it does not recognise, cannot know what the value is, and a stray
`POSTERN_` name is exactly where an unrelated token ends up.

Names are matched byte for byte, so `postern_require_redis` is caught and told
why. The asymmetry with `bool_from_env`, which lower-cases values, is
deliberate: a value is a token for this program to interpret, and a name is a
key the operating system matches exactly.

## Consequence

The guard runs before the write path's authentication guard, so an operator
with both a typo and an incomplete configuration hears about the typo first.
Cost is 27 microseconds over a 72-key environment.

**What it cannot do, and this is the mirror image of what it closes:** it fires
on a name that is present and wrong, never on one that is absent and needed.
For all three flags, "absent" and "deliberately off" are the same state, so an
operator whose environment file failed to load or whose ConfigMap key was
dropped gets silence from this control and from every other. Closing that needs
a second inventory -- what a deployment INTENDS to set -- which only the
operator can own.

Also outside it: `migrations/env.py` reads `POSTERN_DATABASE_URL` and is not a
composition root, so it gets no guard; in this repository a misspelling falls
back to `alembic.ini`'s placeholder and fails loudly, but an operator who puts a
real URL there reintroduces the silent case. `stub/backend.py` is
developer-only and has no guard. And a `postern_core` variable read by a library
both services import is recorded as read by both, even where only one builds
the object -- an error direction that can cost a report that was owed and can
never produce a refusal that was not.

---

## Amendment, 27 September 2026: the other direction, and the migration runner

The record above closes a name that is PRESENT AND WRONG. This closes what can
be closed of the mirror -- a name that is ABSENT AND NEEDED -- and extends both
halves to `migrations/env.py`.

THE HONEST SCOPE IS MUCH NARROWER THAN THE IDEA SOUNDS, and checking the
premise changed the design. A list that lives in the environment cannot guard
the environment's own existence: drop the ConfigMap and `POSTERN_REQUIRED_ENV`
goes with it. That is the case the idea is usually sold on and the mechanism is
vacuous against it.

Measured instead: an empty environment is already fatal on both services --
`KeyError: 'POSTERN_BACKEND_BASE_URL'` on the read path, because that read is a
subscript rather than a `.get`, and the assertion guard on the write path. So
the remaining population is exactly one: A SINGLE KEY DROPPED OR RENAMED ON A
VARIABLE THAT HAS A DEFAULT. Every member of it is a control being disarmed --
`POSTERN_REQUIRE_REDIS` gone means per-replica state accepted,
`POSTERN_REQUIRE_PEM_KEY` gone means an ephemeral signing key,
`POSTERN_REDIS_URL` gone means four stores in memory, `POSTERN_JWKS_URI` gone
means the read path serving with no customer authentication.

WHAT THE APPLICATION CHECKS THAT A PIPELINE CANNOT, since the manifest is still
the pipeline's to assert. What actually reached the process: between a manifest
and `os.environ` sit ECS secrets resolution, Vault sidecar injection, `env_file`
parsing, an entrypoint script and a `docker run -e` someone typed, so a
variable can be right in the manifest and absent in the process. The names are
ours: only the application holds `INVENTORY`, so only it can say "this
requirement names a variable nothing reads, did you mean X" without a second
copy of 57 names. And it travels with the image, where a pipeline check is
per-operator work.

PRESENT MEANS CARRYING A VALUE. Empty does not satisfy a requirement, and the
argument is not consistency with the readers -- though they are unanimous -- but
that AN EMPTY VALUE IS WHAT THE FAILURE BEING GUARDED AGAINST PRODUCES. A Helm
value with nothing behind it, `"value": ""` in a task definition, an `env_file`
line left as `POSTERN_REDIS_URL=`: all emit empty. If empty satisfied the
requirement, the control would pass in the single most likely shape of the
defect. Absent and blank are reported separately, because "nothing set this"
and "something set this to nothing" send an operator to different files.

THE TWO HALVES COVER EACH OTHER, and this was not designed. A typo in the
requirement list is caught either way: set the misspelt variable and the
namespace half refuses it as unread; leave it unset and that half cannot see it
at all, while the requirement half refuses the entry as unsatisfiable -- no
value could ever meet it. Neither half alone covers both. The hatch cannot
launder it either: `ALLOWED_UNREAD_ENV` stops a variable being refused as
unread but cannot put a name into `INVENTORY`, which is what a requirement
needs.

Population 2 keeps its ruling for the same reason as before: a requirement
naming a variable the OTHER service reads is reported and never fatal, because
one requirement list across two deployables is what an operator with one env
file writes. The cost, stated: a dropped key belonging to the other service is
not caught. One list per service buys that.

One flat list, no "one of these". The two cases that would want a combinator
already have purpose-built controls that say it better --
`POSTERN_REQUIRE_PEM_KEY` for "a persisted key or a generated one", and
`services/api/server.py` for "JWKS and issuer together or neither". A boolean
language in an environment variable would be a second, weaker way to say what
those already say.

THE MIGRATION RUNNER, which had the worst failure mode left. `migrations/env.py`
reads `POSTERN_DATABASE_URL` and is not a composition root, so it had no guard;
an operator who puts a real URL in their own `alembic.ini` reintroduces the
silent case and `alembic upgrade` migrates whatever that names.
`enforce_known_environment(service="migrations")` now runs at the top of that
module, BEFORE the URL read, and `SERVICES` has a third member. Verified by
running it: a misspelt `POSTERN_DATABASE_UR` refuses inside `env.py` with the
nearest name, no engine built and no database contacted. The consequence is
deliberate -- `alembic upgrade` exits non-zero, the one-off task fails and the
deploy stops before the migration runs and before the application rolls out
behind it.

The migration task's environment is narrow on evidence rather than assumption:
importing `postern_core.store.models` pulls in ten `postern_core` modules and
not one contains an environment read.

WHAT REMAINS, and the top of the list is now an operator omission rather than
an application gap: a requirement list nobody wrote declares nothing, and the
silence from where the operator stands is the same. Below it, unchanged: a
`postern_core` variable reachable by only one service is recorded as read by
both, because the library that reads it is imported by both; a warning on
population 2 that nobody reads; a name deliberately declared in the hatch;
`stub/backend.py`, which has no guard and is outside the swept roots; and a
correct name carrying a plausible wrong value, where presence is now checkable
and correctness is not.

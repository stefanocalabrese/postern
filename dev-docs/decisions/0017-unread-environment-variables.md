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

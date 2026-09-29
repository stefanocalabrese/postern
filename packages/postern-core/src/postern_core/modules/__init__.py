"""The module seam: how a tool family reaches Postern without forking it.

READ THIS FIRST IF YOU ARE WRITING A MODULE. The two sections at the bottom
are what you are trusted with and what you can break; they are not boilerplate
and they are not going to be softened.

WHAT A MODULE IS. An installed Python distribution that declares an entry
point. Two groups exist, and they are separate on purpose:

    [project.entry-points."postern.read_modules"]
    cards = "postern_cards:MODULE"          # a `postern_core.modules.read.ReadModule`

    [project.entry-points."postern.write_modules"]
    cards = "postern_cards_write:MODULE"    # a `postern_core.modules.write.WriteModule`

`postern_core.modules.read` carries the read half's types and loader;
`postern_core.modules.write` carries the write half's. This package's
``__init__`` imports NEITHER, which is not tidiness: `.importlinter` forbids
``services.api`` from reaching `postern_core.modules.write`, and an import here
would put it in the read path's graph for every module in the tree at once.

ONE MODULE, TWO DISTRIBUTIONS, and the loader enforces it. A single wheel
declaring both groups is refused by
`postern_core.modules.read.refuse_distributions_declaring_both_halves`. The
reason is the image split, not taste: ``site-packages`` is copied whole into
both container images, so a wheel carrying both halves puts backend write
routing inside the read container no matter what the Dockerfile copies. Two
distributions let a deployment install the read half alone, which is the only
arrangement in which "the read process cannot reach a backend write endpoint"
survives contact with a third-party module.

WHY ENTRY POINTS AND NOT A REGISTRATION CALL. CLAUDE.md's hard rule is that
tool definitions are static config versioned in the repo, never registered at
runtime by backend services. An entry point is resolved by
``importlib.metadata`` during import of the composition root, out of the
distributions present in the image, before the first request is served. It
reaches no network, reads no configuration an operator can change after boot,
and cannot vary between two replicas of the same image. The second half of
that rule -- the surface must be diffable between deploys -- is what
``tool-surface.json`` and its gate are for: the file is regenerated from the
assembled server, so a module addition shows up as a reviewable diff naming
every tool, its consent domain, its annotations and its write routing.

WHAT YOU GET FOR FREE, and none of it is optional for you:

- CONSENT. Declare `consent_domain` on each read tool and the host wraps the
  tool in the Postgres-backed check. You cannot opt out by leaving it unset;
  ``None`` means "this tool is reachable with no consent row", which only
  `start_session` has any business being.
- AUDIT. Two rows per call, written by middleware the host installs around
  every registered tool. Your handler is inside it; you write nothing.
- MASKING. `postern_core.domain.masking`'s types mask on construction, and
  `tests/test_masking_golden.py` enumerates whatever the assembled server
  registers -- your tools included. Adding a tool without a masking fixture
  fails the build, and that is deliberate.
- RISK. Per-session budgets and IP anomaly detection run in middleware. Call
  `postern_core.risk.session.get_current_session` and record your row count if
  you want the budget to see it.

=========================================================================
TRUST: A MODULE IS NOT SANDBOXED. THERE IS NO ISOLATION AND NONE IS PLANNED.
=========================================================================

A module runs in the same process, in the same interpreter, with the same
memory as the service that loaded it. Python offers no boundary that would
change this, and this project has deliberately not built a half-one.

So a module you install can, with no exploit and no bug on anyone's part:

- read the signing key material the process holds, because
  `postern_core.auth.keys`' key source objects are reachable from any imported
  module through ordinary attribute access;
- mint an internal JWT for any audience the loading process has a key for;
- read or write any row the process's database credential can reach,
  ``audit_log`` inserts included;
- monkey-patch masking, consent or audit, because nothing here is immutable at
  runtime;
- open a socket to anywhere the container's egress policy allows.

The read process holds a READ key and cannot mint a write token, so a module
installed only on the read path cannot move money -- that bound comes from the
key split and from the image not carrying the write half, NOT from anything in
this seam. A module installed on the write path is inside the write blast
radius in full.

WHAT FOLLOWS FROM THAT, for an operator: installing a module is exactly as
consequential as merging a commit into this repository. Review it, pin it by
hash, build it into your own image, and do not let the module list be
something a deploy can change without a diff. The `tool-surface.json` gate is
what makes the surface half of that reviewable; nothing makes the code half
reviewable except reading it.

WHAT THIS IS NOT: a permission model, a capability system, a sandbox, or a
step towards one. Those are a separate and much larger question, and a
half-built sandbox is worse than this warning, because it invites the trust
this text is trying to refuse.
"""

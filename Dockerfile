# Three images from one repository and one build, differing in what the final
# stage carries (handoff §12.2): an RCE in the read (`api`) container must not
# even find the write path's (`confirm`) code, and neither serving container
# may hold the tool that can undo the `audit_log` protections.
#
# That is a property of the copy layer below and of nothing else. It was false
# until 26 September 2026: `runtime` did `COPY --from=builder /app /app` and
# both targets inherited it, so each image held the other service in full.
# Measured on the built image before the change, `/app/services/confirm` in
# the `api` image listed all fifteen of its modules. `.importlinter`'s three
# contracts enforce the same separation in source, and an image built this way
# threw their result away at the last step.
#
# `services/confirm` is the entire write path now, not the empty package an
# earlier version of this header described: the RFC 8628 device grant, the
# approval callback that reaches a backend write endpoint, two rate limiters,
# the Ed25519 device-signature check and the audit writers.
#
# The runtime stages copy named paths instead of a tree, which fails closed.
# A file nobody names is absent whether or not `.dockerignore` remembers it,
# and that is how `.grimp_cache` (this project's complete import graph,
# `services.confirm` module names and all), `.remember` (session logs, mode
# 700 on the host) and a stray `nonexistent/Library/...` tree stopped being
# shipped -- none of the three was excluded and all three were in the image.
# `.dockerignore` still earns its place, because the deploy workflow exports
# build cache with `mode=max`, which pushes intermediate builder layers to
# ECR; it is no longer the only thing standing between the context and a
# shipped image.
#
# The third image, `migrate`, exists because the second version of this split
# left a hole the first one hid. Both serving images carried `migrations/` and
# the `alembic` console script, and the `api` service holds
# `POSTERN_DATABASE_URL` because it needs one. Revision `f1860c110112` is what
# makes `audit_log` refuse `UPDATE`, `DELETE` and `TRUNCATE`, and its own
# `downgrade` says what reversing it costs: "after this runs, any SQL
# injection or RCE in either service can erase the rows recording the calls it
# made." An attacker in the read container had the scripts, the runner and the
# credential in one place. Now the runner and the scripts live in an image
# that serves no traffic and runs as a one-off task, and the serving images
# hold neither.
#
# OPERATOR: `migrate` needs its own ECR repository, `postern-migrate`, beside
# `postern-api` and `postern-confirm`, and its own ECS task definition run as
# a one-off task rather than a service. It is the only one of the three that
# should ever be given a database URL with DDL rights.
#
# Base images are pinned by digest, not tag (handoff §12.2); see
# dev-docs/decisions/0004-base-images.md for the resolved digests, the date
# they were resolved, and why both cover linux/arm64.

FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim@sha256:e5b65587bce7de595f299855d7385fe7fca39b8a74baa261ba1b7147afa78e58 AS builder
WORKDIR /app
COPY pyproject.toml uv.lock ./
# Every workspace member's `pyproject.toml`, and not just the library's: the
# root project depends on all three through `[tool.uv.sources] workspace = true`,
# and `[tool.uv.workspace] members = ["packages/*"]` globs the directory. A
# member whose manifest is absent from this layer is a member uv cannot resolve,
# so the sync below fails rather than quietly omitting it.
COPY packages/postern-core/pyproject.toml packages/postern-core/
COPY packages/postern-cards/pyproject.toml packages/postern-cards/
COPY packages/postern-cards-write/pyproject.toml packages/postern-cards-write/
# `--frozen` refuses to update `uv.lock`: the build fails instead of silently
# drifting from the committed lockfile. `--no-install-project` alone still
# tries to build the `postern-core` workspace member from source (measured:
# it fails here with "Expected a Python module at
# packages/postern-core/src/postern_core/__init__.py", because only that
# package's `pyproject.toml` has been copied so far) -- `--no-install-workspace`
# is the flag that actually defers every workspace member, not just the root
# project, so this layer installs only third-party dependencies and stays
# cacheable across source-only changes.
RUN uv sync --frozen --no-dev --no-install-workspace
COPY . .
# `--frozen` again: this second sync installs the workspace project itself
# from the now-complete source tree, still refusing any lockfile update.
RUN uv sync --frozen --no-dev

# A copy of the venv with the migration runner taken out of it, prepared here
# rather than in a serving stage for a reason worth stating: `RUN rm` on top
# of a layer that already holds the files only hides them behind an overlayfs
# whiteout. The bytes stay in the lower layer, and anyone who can pull the
# image can read them back out. Deleting before the copy means the serving
# images never contain alembic at all, at the cost of not sharing the venv
# layer with `migrate`.
#
# Nothing under `services/` or `postern_core` imports alembic -- grepped, and
# the only four matches in the tree are prose inside comments -- so this
# removes a capability and no functionality. Both services are started below
# the way a deploy starts them to show that holds.
FROM builder AS serving-venv
RUN rm -rf /app/.venv/bin/alembic \
           /app/.venv/lib/python3.12/site-packages/alembic \
           /app/.venv/lib/python3.12/site-packages/alembic-*.dist-info

# What all three images need, and nothing any of them does not. Every path
# below was checked against a running image rather than read off the import
# graph, because the graph does not know about `.pth` files or console scripts.
FROM python:3.12-slim@sha256:78387bc3881b8273120a12ebe6c1ab22b018ccc2c9adf565ae1ac9b536e184ea AS runtime
WORKDIR /app
# The source tree two of the venv's `.pth` files point back at. `uv sync`
# installs both workspace members editable: `postern_core.pth` holds
# `/app/packages/postern-core/src` and `postern.pth` holds `/app`. So the
# interpreter reads `postern_core` out of the source tree and not out of
# site-packages, and that tree has to be present for any import to resolve.
# `PYTHONPATH="/app"` below states the second half again; neither alone is
# load-bearing, which is why dropping either one in isolation looks harmless.
COPY --from=builder /app/packages/postern-core/src /app/packages/postern-core/src
# `services` is a regular package, not a namespace one, so without this file
# neither `services.api` nor `services.confirm` imports at all.
COPY --from=builder /app/services/__init__.py /app/services/__init__.py
ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONPATH="/app" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
# Non-root (handoff §12.2). A fixed uid:gid, not a named user: no stage
# creates one, and the numeric form needs no `/etc/passwd` entry to be valid.
# Set once here so every stage built on this one inherits it; a COPY after it
# still runs as root, which is why the venv below lands readable.
USER 1000:1000

# The read path, and only the read path. `services/confirm` is never copied
# into this stage, so an attacker who reaches RCE here finds no write-path
# module to read, import or reuse, and the venv it takes is the one with no
# migration runner in it.
#
# Both serving stages repeat the venv copy rather than sharing an intermediate
# `serving` stage, and that is not a style choice: `tests/test_zt3_digest_drift`
# decides whether a `FROM` names an external image by comparing against the
# literal set `("runtime", "builder")`, so any third internal stage name in a
# `FROM` line is read as an unpinned external image and fails the digest gate.
# `serving-venv` is fine because it is only ever a `--from=` target. The two
# copies are byte-identical, so both images share the layer.
FROM runtime AS api
COPY --from=serving-venv /app/.venv /app/.venv
COPY --from=builder /app/services/api /app/services/api
# The cards MODULE's read half, and not its write half. This is the image-level
# expression of the module seam's share of the key split, and it works because
# `uv sync` installs a workspace member editable: the venv holds a
# `postern_cards_write.pth` pointing at a source directory this image does not
# copy, so `import postern_cards_write` raises `ModuleNotFoundError` here. A
# single distribution declaring both entry-point groups would defeat that --
# `site-packages` is copied whole -- which is why
# `postern_core.modules.read.refuse_distributions_declaring_both_halves` refuses
# one. `tests/test_module_halves_in_images.py` holds every module pair in
# `packages/` to this rule, derived from the tree rather than listed, so the next
# module pair is covered without editing that file.
COPY --from=builder /app/packages/postern-cards/src /app/packages/postern-cards/src
CMD ["uvicorn", "services.api.main:app", "--host", "0.0.0.0", "--port", "8080"]

# The write path, and only the write path. The read service's tool handlers,
# consent checks and MCP surface are absent here for the same reason.
FROM runtime AS confirm
COPY --from=serving-venv /app/.venv /app/.venv
COPY --from=builder /app/services/confirm /app/services/confirm
# The cards module's write half, and not its read half. What this container holds
# of the cards module is three routes -- audience, path, method, tier -- and no
# tool, no handler and no MCP surface.
COPY --from=builder /app/packages/postern-cards-write/src /app/packages/postern-cards-write/src
CMD ["uvicorn", "services.confirm.main:app", "--host", "0.0.0.0", "--port", "8080"]

# The migration runner: the whole venv, the scripts, and no service. It serves
# no port and carries no request handler, so there is nothing in it to reach
# over the network. `alembic.ini` resolves `script_location` to
# `%(here)s/migrations`, and `migrations/env.py` imports
# `postern_core.store.models` to register the tables on the metadata, which is
# why this stage needs the library the serving images also carry.
FROM runtime AS migrate
COPY --from=builder /app/.venv /app/.venv
COPY --from=builder /app/alembic.ini /app/alembic.ini
COPY --from=builder /app/migrations /app/migrations
CMD ["alembic", "upgrade", "head"]

# Two images from one repository and one build, differing in which service's
# code the final stage carries (handoff §12.2): an RCE in the read (`api`)
# container must not even find the write path's (`confirm`) code.
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
# Base images are pinned by digest, not tag (handoff §12.2); see
# dev-docs/decisions/0004-base-images.md for the resolved digests, the date
# they were resolved, and why both cover linux/arm64.

FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim@sha256:e5b65587bce7de595f299855d7385fe7fca39b8a74baa261ba1b7147afa78e58 AS builder
WORKDIR /app
COPY pyproject.toml uv.lock ./
COPY packages/postern-core/pyproject.toml packages/postern-core/
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

# What both services need, and nothing either of them does not. Every path
# below was checked against a running image rather than read off the import
# graph, because the graph does not know about `.pth` files or alembic.
FROM python:3.12-slim@sha256:78387bc3881b8273120a12ebe6c1ab22b018ccc2c9adf565ae1ac9b536e184ea AS runtime
WORKDIR /app
# The virtualenv, and the source tree two of its `.pth` files point back at.
# `uv sync` installs both workspace members editable: `postern_core.pth` holds
# `/app/packages/postern-core/src` and `postern.pth` holds `/app`. So the
# interpreter reads `postern_core` out of the source tree and not out of
# site-packages, and that tree has to be present for any import to resolve.
# `PYTHONPATH="/app"` below states the second half again; neither alone is
# load-bearing, which is why dropping either one in isolation looks harmless.
COPY --from=builder /app/.venv /app/.venv
COPY --from=builder /app/packages/postern-core/src /app/packages/postern-core/src
# `alembic upgrade head` runs from this image as a one-off task, so its two
# inputs stay: `alembic.ini` resolves `script_location` to
# `%(here)s/migrations`, and `migrations/env.py` imports
# `postern_core.store.models` to register the tables. Neither service imports
# either path at run time -- grepped, not assumed -- so these are a deploy
# path being kept rather than a runtime dependency being satisfied.
COPY --from=builder /app/alembic.ini /app/alembic.ini
COPY --from=builder /app/migrations /app/migrations
# `services` is a regular package, not a namespace one, so without this file
# neither `services.api` nor `services.confirm` imports at all.
COPY --from=builder /app/services/__init__.py /app/services/__init__.py
ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONPATH="/app" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
# Non-root (handoff §12.2). A fixed uid:gid, not a named user: neither stage
# creates one, and the numeric form needs no `/etc/passwd` entry to be valid.
USER 1000:1000

# The read path, and only the read path. `services/confirm` is never copied
# into this stage, so an attacker who reaches RCE here finds no write-path
# module to read, import or reuse.
FROM runtime AS api
COPY --from=builder /app/services/api /app/services/api
CMD ["uvicorn", "services.api.main:app", "--host", "0.0.0.0", "--port", "8080"]

# The write path, and only the write path. The read service's tool handlers,
# consent checks and MCP surface are absent here for the same reason.
FROM runtime AS confirm
COPY --from=builder /app/services/confirm /app/services/confirm
CMD ["uvicorn", "services.confirm.main:app", "--host", "0.0.0.0", "--port", "8080"]

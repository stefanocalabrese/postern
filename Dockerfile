# Two images from one repo, same source, different final stage (handoff
# §12.2): an RCE in the read (`api`) container must not even find the write
# path's (`confirm`) code. `services/confirm` has no code yet in this plan
# (Task 13's own decision record explains what that means for the `confirm`
# target today); the split is real in the registry from the first build
# regardless.
#
# Base images are pinned by digest, not tag (handoff §12.2); see
# docs/decisions/0004-base-images.md for the resolved digests, the date they
# were resolved, and why both cover linux/arm64.

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

FROM python:3.12-slim@sha256:78387bc3881b8273120a12ebe6c1ab22b018ccc2c9adf565ae1ac9b536e184ea AS runtime
WORKDIR /app
COPY --from=builder /app /app
ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONPATH="/app" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
# Non-root (handoff §12.2). A fixed uid:gid, not a named user: neither stage
# creates one, and the numeric form needs no `/etc/passwd` entry to be valid.
USER 1000:1000

FROM runtime AS api
CMD ["uvicorn", "services.api.main:app", "--host", "0.0.0.0", "--port", "8080"]

FROM runtime AS confirm
CMD ["uvicorn", "services.confirm.main:app", "--host", "0.0.0.0", "--port", "8080"]

"""ZT-3 — Workload attestation: base image digest drift detection.

Verifies that the Dockerfile's external base images are pinned by sha256
digest (not tag) and that the digests match the known-good values recorded
in ``dev-docs/decisions/0004-base-images.md``.

This is the only part of ZT-3 that can be tested in this repo:
- Cosign verification at deploy time is blocked on there being a deploy
  to gate (CLAUDE.md gate 7).
- SBOM/Trivy scanning is blocked on CI tooling (CLAUDE.md gate 7).
- IAM policy test is blocked on the Terraform repo (CLAUDE.md gate 5).

The digest drift check is a pure-text assertion: if someone changes the
Dockerfile to use ``python:3.12-slim`` (tag) instead of the pinned digest,
this test fails before the image is even built.

See ``dev-docs/decisions/0004-base-images.md`` for the resolved digests and
the rationale for why both are multi-arch manifest-list digests.
"""

from __future__ import annotations

import re
from pathlib import Path

# Known-good digests from dev-docs/decisions/0004-base-images.md.
# These are the values that were resolved on 2026-09-14 and committed
# into the Dockerfile. Any drift here means someone bumped a tag
# without re-resolving and updating the decision record.
_KNOWN_DIGESTS: dict[str, str] = {
    "ghcr.io/astral-sh/uv:python3.12-bookworm-slim": (
        "sha256:e5b65587bce7de595f299855d7385fe7fca39b8a74baa261ba1b7147afa78e58"
    ),
    "python:3.12-slim": ("sha256:78387bc3881b8273120a12ebe6c1ab22b018ccc2c9adf565ae1ac9b536e184ea"),
}

# Regex: FROM <image>@sha256:<hex> AS <name>
# Match image as everything up to @ (digest separator) or whitespace.
_FROM_RE = re.compile(
    r"^FROM\s+"
    r"(?P<image>[^\s@]+)"
    r"(?:@(?P<digest>sha256:[a-f0-9]+))?"
    r"(?:\s+AS\s+\S+)?",
    re.MULTILINE,
)


def _read_dockerfile() -> str:
    """Return the Dockerfile contents."""
    return Path(__file__).resolve().parents[1].joinpath("Dockerfile").read_text()


# --- External images must be pinned by digest (not tag) ---


def test_all_external_from_lines_use_digests() -> None:
    """Every external FROM line uses @sha256:, not a bare tag."""
    dockerfile = _read_dockerfile()
    for m in _FROM_RE.finditer(dockerfile):
        image = m.group("image")
        digest = m.group("digest")

        # Multi-stage references (e.g. "FROM runtime AS api") are internal
        # and don't need digest pinning — they resolve to a build stage.
        if image in ("runtime", "builder"):
            continue

        assert digest is not None, (
            f"External image '{image}' in FROM line is not pinned by "
            "digest — use @sha256:<hex>, not a tag."
        )


# --- Digests must match the known-good values in the decision record ---


def test_digests_match_decision_record() -> None:
    """Dockerfile digests match dev-docs/decisions/0004-base-images.md."""
    dockerfile = _read_dockerfile()

    found: dict[str, str] = {}
    for m in _FROM_RE.finditer(dockerfile):
        image = m.group("image")
        digest = m.group("digest")

        if image in ("runtime", "builder"):
            continue

        assert digest is not None, f"External image '{image}' in FROM line is not pinned by digest."
        found[image] = digest

    for image, expected_digest in _KNOWN_DIGESTS.items():
        actual = found.get(image)
        assert actual == expected_digest, (
            f"Digest drift detected for '{image}': "
            f"Dockerfile has {actual!r}, decision record expects "
            f"{expected_digest!r}. Re-resolve with "
            "'docker buildx imagetools inspect' and update both files."
        )


# --- Decision record must list all external images ---


def test_decision_record_lists_all_external_images() -> None:
    """Every external image in the Dockerfile is documented."""
    dockerfile = _read_dockerfile()

    found: dict[str, str] = {}
    for m in _FROM_RE.finditer(dockerfile):
        image = m.group("image")
        digest = m.group("digest")

        if image in ("runtime", "builder"):
            continue

        assert digest is not None, f"External image '{image}' in FROM line is not pinned by digest."
        found[image] = digest

    for image in found:
        assert image in _KNOWN_DIGESTS, (
            f"External image '{image}' is pinned by digest in the Dockerfile "
            "but not listed in dev-docs/decisions/0004-base-images.md. Add it."
        )


# --- No bare tags anywhere in FROM lines ---


def test_no_bare_tags_in_from_lines() -> None:
    """No FROM line uses a bare tag without digest."""
    dockerfile = _read_dockerfile()

    for m in _FROM_RE.finditer(dockerfile):
        image = m.group("image")
        digest = m.group("digest")

        if image in ("runtime", "builder"):
            continue

        # If the image string itself contains @sha256, that's fine.
        if "@sha256:" in image:
            continue

        assert digest is not None, (
            f"FROM line for '{image}' uses a bare tag without digest pinning. "
            "Replace with @sha256:<resolved-digest>."
        )

"""ZT-3 — Deploy pipeline: cosign, SBOM, Trivy gates.

Validates that ``.github/workflows/deploy.yml`` contains all required ZT-3
gates as text-level assertions. This is the code-level half of gate 7:

- Gate 7a (digest drift): ``test_zt3_digest_drift.py`` — Dockerfile FROM lines
- Gate 7b (cosign sign + verify): this file — deploy workflow gates
- Gate 7c (SBOM presence): this file — syft + artifact checks

The workflow must:
1. Sign images with cosign (keyless/OIDC) after push.
2. Verify cosign signatures before deploy (hard gate).
3. Generate SBOMs with syft and upload as artifacts.
4. Scan images for HIGH/CRITICAL vulnerabilities with Trivy.

See ``dev-docs/decisions/0011-deploy-pipeline.md`` for the full design.
"""

from __future__ import annotations

import re
from pathlib import Path

_WORKFLOW_PATH = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "deploy.yml"


def _read_workflow() -> str:
    """Return the deploy workflow contents."""
    return _WORKFLOW_PATH.read_text()


# ── Cosign signing gates ──────────────────────────────────────────


def test_workflow_installs_cosign() -> None:
    """The workflow installs cosign (sigstore/cosign-installer)."""
    content = _read_workflow()
    assert "sigstore/cosign-installer" in content, (
        "Deploy workflow must install cosign for image signing and verification."
    )


def test_workflow_signs_api_image() -> None:
    """The workflow runs ``cosign sign`` for the api image."""
    content = _read_workflow()
    assert re.search(r"cosign\s+sign", content), (
        "Deploy workflow must sign the api image with cosign."
    )
    assert "postern-api" in content, "Cosign sign step must target the postern-api image."


def test_workflow_signs_confirm_image() -> None:
    """The workflow runs ``cosign sign`` for the confirm image."""
    content = _read_workflow()
    assert re.search(r"cosign\s+sign", content), (
        "Deploy workflow must sign the confirm image with cosign."
    )
    assert "postern-confirm" in content, "Cosign sign step must target the postern-confirm image."


def test_workflow_uses_keyless_cosign() -> None:
    """Cosign signing uses keyless mode (OIDC from GitHub Actions)."""
    content = _read_workflow()
    # Keyless mode: either COSIGN_EXPERIMENTAL=1 or --certificate-identity
    # The workflow should use OIDC-based keyless signing, not static keys.
    has_oidc = "token.actions.githubusercontent.com" in content or (
        "COSIGN_EXPERIMENTAL" in content and "cosign sign" in content
    )
    assert has_oidc, (
        "Cosign signing must use keyless mode (OIDC from GitHub Actions), not static keys."
    )


# ── Cosign verification gates (ZT-3 hard gate) ───────────────────


def test_workflow_verifies_cosign_before_deploy() -> None:
    """The deploy stage verifies cosign signatures before deploying."""
    content = _read_workflow()
    assert re.search(r"cosign\s+verify", content), (
        "Deploy workflow must verify cosign signatures before deployment. "
        "This is the ZT-3 hard gate — reject unsigned or tampered images."
    )


def test_workflow_verifies_api_signature() -> None:
    """Cosign verification targets the api image."""
    content = _read_workflow()
    assert re.search(r"cosign\s+verify.*postern-api", content) or (
        "cosign verify" in content and "postern-api" in content
    ), "Cosign verify step must target the postern-api image."


def test_workflow_verifies_confirm_signature() -> None:
    """Cosign verification targets the confirm image."""
    content = _read_workflow()
    assert re.search(r"cosign\s+verify.*postern-confirm", content) or (
        "cosign verify" in content and "postern-confirm" in content
    ), "Cosign verify step must target the postern-confirm image."


def test_workflow_verifies_against_sigstore_transparency_log() -> None:
    """Verification checks the Sigstore Rekor transparency log."""
    content = _read_workflow()
    assert "rekor.sigstore.dev" in content or "rekor-url" in content, (
        "Cosign verification must check the Sigstore Rekor transparency log (not just a local key)."
    )


# ── SBOM gates ───────────────────────────────────────────────────


def test_workflow_generates_sbom_with_syft() -> None:
    """The workflow generates SBOMs (syft or anchore/sbom-action)."""
    content = _read_workflow()
    assert "syft" in content or "anchore/sbom-action" in content, (
        "Deploy workflow must generate SBOMs using syft or anchore/sbom-action."
    )


def test_workflow_uses_spdx_format() -> None:
    """SBOMs are generated in SPDX format (industry standard)."""
    content = _read_workflow()
    assert "spdx" in content.lower(), "SBOMs must be in SPDX format for auditor compatibility."


def test_workflow_uploads_sbom_as_artifacts() -> None:
    """SBOMs are uploaded as workflow artifacts for audit retention."""
    content = _read_workflow()
    assert "upload-artifact" in content, (
        "SBOMs must be uploaded as workflow artifacts for audit retention."
    )


def test_workflow_checks_sbom_presence_before_deploy() -> None:
    """The deploy stage checks that SBOMs exist before proceeding."""
    content = _read_workflow()
    # The deploy stage must verify SBOM artifacts are present.
    has_download = "download-artifact" in content
    has_sbom_check = ("sbom-" in content and "test -f" in content) or ("SBOM missing" in content)
    assert has_download and has_sbom_check, (
        "Deploy stage must download SBOM artifacts and verify their presence. "
        "A missing SBOM blocks deployment."
    )


# ── Vulnerability scanning gates ─────────────────────────────────


def test_workflow_scans_with_trivy() -> None:
    """The workflow scans images for vulnerabilities (Trivy)."""
    content = _read_workflow()
    assert "trivy" in content.lower(), (
        "Deploy workflow must scan images for vulnerabilities using Trivy."
    )


def test_workflow_blocks_on_high_severity() -> None:
    """Trivy scanning blocks the build on HIGH/CRITICAL vulnerabilities."""
    content = _read_workflow()
    assert "exit-code" in content and '"1"' in content, (
        "Trivy must exit with code 1 on HIGH/CRITICAL findings to block the build."
    )
    # Check that severity filter includes HIGH and CRITICAL.
    has_high = "HIGH" in content
    has_critical = "CRITICAL" in content or "critical" in content.lower()
    assert has_high and has_critical, (
        "Trivy must scan for HIGH and CRITICAL severity vulnerabilities."
    )


# ── Structural gates ─────────────────────────────────────────────


def test_workflow_has_build_and_deploy_stages() -> None:
    """The workflow has separate build and deploy jobs."""
    content = _read_workflow()
    assert "build:" in content, "Deploy workflow must have a 'build' job."
    assert "deploy:" in content, "Deploy workflow must have a 'deploy' job."


def test_deploy_requires_environment_approval() -> None:
    """The deploy job uses GitHub Environments for manual approval."""
    content = _read_workflow()
    assert "environment:" in content, (
        "Deploy job must use GitHub Environments for manual approval gates. "
        "Production deploys require human sign-off."
    )


def test_workflow_dispatch_only() -> None:
    """The workflow triggers only on workflow_dispatch (no auto-triggers)."""
    content = _read_workflow()
    # Must have workflow_dispatch and must NOT have push/PR triggers.
    assert "workflow_dispatch" in content, "Deploy workflow must trigger on workflow_dispatch."
    # Extract the 'on:' section (first 500 chars should cover it).
    on_section = content[:500]
    assert "push:" not in on_section, (
        "Deploy workflow must NOT trigger on push (billed minutes on private repo)."
    )
    assert "pull_request:" not in on_section, "Deploy workflow must NOT trigger on pull_request."


def test_workflow_uses_digest_not_tag_for_ecr() -> None:
    """Images are pushed and referenced by sha256 digest, not mutable tags."""
    content = _read_workflow()
    # The workflow should reference images by digest (steps.push-api.outputs.digest).
    assert "outputs.digest" in content or "@sha256:" in content, (
        "Images must be referenced by sha256 digest for immutability. "
        "Mutable tags (latest, main) are not acceptable for deploy targets."
    )


# ── Integration: workflow file must exist and be valid YAML ───────


def test_workflow_file_exists() -> None:
    """The deploy workflow file must exist at the expected path."""
    assert _WORKFLOW_PATH.exists(), (
        f"Deploy workflow not found at {_WORKFLOW_PATH}. Create .github/workflows/deploy.yml."
    )


def test_workflow_file_is_non_empty() -> None:
    """The deploy workflow file must not be empty."""
    content = _read_workflow()
    assert len(content) > 100, "Deploy workflow file is too small — likely empty or incomplete."

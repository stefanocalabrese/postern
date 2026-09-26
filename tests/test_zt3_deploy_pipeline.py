"""ZT-3 — Deploy pipeline: cosign, SBOM, Trivy gates.

Validates that ``.github/workflows/deploy.yml`` contains all required ZT-3
gates. This is the code-level half of gate 7:

- Gate 7a (digest drift): ``test_zt3_digest_drift.py`` — Dockerfile FROM lines
- Gate 7b (cosign sign + verify): this file — deploy workflow gates
- Gate 7c (SBOM presence): this file — syft + artifact checks

The workflow must:
1. Sign images with cosign (keyless/OIDC) after push.
2. Verify cosign signatures before deploy (hard gate), against an identity
   that names THIS repository and THIS workflow.
3. Generate SBOMs with syft and upload as artifacts.
4. Scan images for HIGH/CRITICAL vulnerabilities with Trivy.
5. Pin every action to a commit SHA, and trigger on nothing but dispatch.

WHY THIS FILE PARSES THE YAML

Every assertion here was a substring test against the whole file until
25 September 2026, and on that date two defects had been sitting in the
workflow that this file exists to catch and did not:

- Both Trivy steps read ``uses: aquasecurity/trivy-action@v0``. That ref does
  not exist -- the repository publishes full patch tags only and has no ``v0``
  tag and no ``v0`` branch -- so both steps failed to resolve at run time and
  the vulnerability scan had never once executed. The guard was
  ``"trivy" in content.lower()``, which the surrounding comment satisfied on
  its own, and ``"exit-code" in content and '"1"' in content``, whose second
  half was satisfied by ``COSIGN_EXPERIMENTAL: "1"`` forty lines away in a
  different job.
- Both verify steps read ``--certificate-identity-regexp=".*"``, which accepts
  any signature from anyone holding a GitHub Actions OIDC certificate. The
  guard was ``"cosign verify" in content``, which says nothing about what the
  verification demands.

A substring that appears anywhere in a 300-line file cannot express "this step
passes this value". So the assertions below resolve the document, walk the
steps, and check values on the step that owns them. The remaining text-level
checks are the ones about text -- the trailing version comment beside a SHA
pin, which is a comment and therefore absent from the parsed document.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

_WORKFLOW_DIR = Path(__file__).resolve().parents[1] / ".github" / "workflows"
_WORKFLOW_PATH = _WORKFLOW_DIR / "deploy.yml"
_CI_WORKFLOW_PATH = _WORKFLOW_DIR / "ci.yml"

# The repository this workflow runs in, as `git remote -v` reports it. The
# cosign identity has to name it, so a wrong value here is a failing test and
# not a silently weaker gate.
_REPOSITORY = "stefanocalabrese/postern"

# The Subject Alternative Name a keyless GitHub Actions signature actually
# carries. Fulcio's `Embed` method (pkg/identity/github/principal.go) sets
# `cert.URIs` to the GitHub server URL joined with the `job_workflow_ref`
# claim, so a run of deploy.yml on branch `<b>` signs under
# `https://github.com/<owner>/<repo>/.github/workflows/deploy.yml@refs/heads/<b>`.
_IDENTITY = "https://github.com/{repo}/.github/workflows/{wf}@{ref}".format

# GitHub's OIDC provider. There is exactly one correct value.
_OIDC_ISSUER = "https://token.actions.githubusercontent.com"

# A pinned action ref: a full 40-character commit SHA, lowercase hex.
_SHA_PIN_RE = re.compile(r"\A[0-9a-f]{40}\Z")

# `uses: owner/action@<40 hex>  # vX.Y.Z` -- the form commit 8ed7f4e set, whose
# trailing comment is what dependabot matches on to bump the pin.
_PINNED_USES_LINE_RE = re.compile(
    r"^\s*(?:-\s+)?uses:\s*(?P<action>[^@\s]+)@(?P<ref>\S+)(?P<comment>.*)$",
    re.MULTILINE,
)


def _read_workflow() -> str:
    """Return the deploy workflow contents."""
    return _WORKFLOW_PATH.read_text()


def _parse(path: Path) -> dict[Any, Any]:
    """Return a workflow file as a parsed document."""
    doc = yaml.safe_load(path.read_text())
    assert isinstance(doc, dict), f"{path.name} did not parse to a mapping"
    return doc


def _triggers(doc: dict[Any, Any]) -> dict[Any, Any]:
    """Return a workflow's `on:` mapping.

    YAML 1.1 resolves a bare ``on`` key to the boolean ``True``, which is why
    the old substring check never looked at this mapping and settled for
    scanning the first 500 characters of the file instead. Both spellings are
    accepted here so the test does not depend on that quirk.
    """
    for key in (True, "on"):
        if key in doc:
            triggers = doc[key]
            assert isinstance(triggers, dict), "`on:` did not parse to a mapping"
            return triggers
    raise AssertionError("workflow declares no `on:` block")


def _steps(doc: dict[Any, Any]) -> list[tuple[str, dict[Any, Any]]]:
    """Return every step in the document, paired with its job name."""
    out: list[tuple[str, dict[Any, Any]]] = []
    for job_name, job in doc["jobs"].items():
        for step in job.get("steps", []):
            out.append((str(job_name), step))
    return out


def _steps_using(doc: dict[Any, Any], action_prefix: str) -> list[dict[Any, Any]]:
    """Return every step whose `uses:` names the given action."""
    return [step for _, step in _steps(doc) if str(step.get("uses", "")).startswith(action_prefix)]


def _run_scripts_containing(doc: dict[Any, Any], needle: str) -> list[str]:
    """Return every step's `run:` script that contains the given text."""
    return [
        str(step["run"]) for _, step in _steps(doc) if "run" in step and needle in str(step["run"])
    ]


# One of this repository's two images, followed by the character that decides
# how it is addressed: `@` is a digest, `:` is a tag.
_IMAGE_REF_RE = re.compile(r"postern-(?:api|confirm)(?P<sep>[:@])")

# The three step inputs whose whole job is to name a tag. `tags:` is what the
# push step applies, and the two cache refs address a buildcache manifest that
# has no digest to address it by. Every other mention of an image is a
# consumer of one and owes a digest.
_TAG_ADDRESSED_KEYS = frozenset({"tags", "cache-from", "cache-to"})

# `${{ steps.<id>.outputs.digest }}`, the only digest source inside `build`.
_DIGEST_EXPR_RE = re.compile(r"steps\.([A-Za-z0-9_-]+)\.outputs\.digest")


def _step_scalars(step: dict[Any, Any]) -> list[tuple[str, str]]:
    """Return every string a step carries, paired with the key that holds it.

    One level of nesting is enough: `with:` and `env:` are mappings of
    scalars, and `run:` is a scalar itself.
    """
    out: list[tuple[str, str]] = []
    for key, value in step.items():
        if isinstance(value, str):
            out.append((str(key), value))
        elif isinstance(value, dict):
            out.extend((str(k), v) for k, v in value.items() if isinstance(v, str))
    return out


def _flag_value(script: str, flag: str) -> str | None:
    """Return the value a shell script passes to ``--flag=value``.

    Handles the single-quoted, double-quoted and bare forms, because the
    quoting is what stops the shell expanding a `$` anchor in a regex.
    """
    match = re.search(
        rf"{re.escape(flag)}=(?:'([^']*)'|\"([^\"]*)\"|(\S+))",
        script,
    )
    if match is None:
        return None
    return next(group for group in match.groups() if group is not None)


# ── Cosign signing gates ──────────────────────────────────────────


def test_workflow_installs_cosign() -> None:
    """The workflow installs cosign (sigstore/cosign-installer)."""
    content = _read_workflow()
    assert "sigstore/cosign-installer" in content, (
        "Deploy workflow must install cosign for image signing and verification."
    )


def test_workflow_signs_api_image() -> None:
    """The workflow runs ``cosign sign`` for the api image."""
    scripts = _run_scripts_containing(_parse(_WORKFLOW_PATH), "cosign sign")
    assert any("postern-api" in script for script in scripts), (
        "Deploy workflow must sign the api image with cosign."
    )


def test_workflow_signs_confirm_image() -> None:
    """The workflow runs ``cosign sign`` for the confirm image."""
    scripts = _run_scripts_containing(_parse(_WORKFLOW_PATH), "cosign sign")
    assert any("postern-confirm" in script for script in scripts), (
        "Deploy workflow must sign the confirm image with cosign."
    )


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
    doc = _parse(_WORKFLOW_PATH)
    verify_steps = [
        (job, step)
        for job, step in _steps(doc)
        if "run" in step and "cosign verify" in str(step["run"])
    ]
    assert verify_steps, (
        "Deploy workflow must verify cosign signatures before deployment. "
        "This is the ZT-3 hard gate — reject unsigned or tampered images."
    )
    assert all(job == "deploy" for job, _ in verify_steps), (
        "Verification must run in the deploy job, which is the one gated by a "
        "GitHub Environment. Verifying inside build gates nothing."
    )


def test_workflow_verifies_api_signature() -> None:
    """Cosign verification targets the api image."""
    scripts = _run_scripts_containing(_parse(_WORKFLOW_PATH), "cosign verify")
    assert any("postern-api" in script for script in scripts), (
        "Cosign verify step must target the postern-api image."
    )


def test_workflow_verifies_confirm_signature() -> None:
    """Cosign verification targets the confirm image."""
    scripts = _run_scripts_containing(_parse(_WORKFLOW_PATH), "cosign verify")
    assert any("postern-confirm" in script for script in scripts), (
        "Cosign verify step must target the postern-confirm image."
    )


def test_workflow_verifies_against_sigstore_transparency_log() -> None:
    """Verification checks the Sigstore Rekor transparency log."""
    content = _read_workflow()
    assert "rekor.sigstore.dev" in content or "rekor-url" in content, (
        "Cosign verification must check the Sigstore Rekor transparency log (not just a local key)."
    )


def test_cosign_verify_constrains_the_signing_identity() -> None:
    """Every ``cosign verify`` names an identity, and not a catch-all.

    ``--certificate-identity-regexp=".*"`` shipped here until 25 September
    2026. It proves an image was signed by somebody holding a GitHub Actions
    OIDC certificate -- which is anyone who can run a workflow in any public
    repository -- and says nothing about who.
    """
    scripts = _run_scripts_containing(_parse(_WORKFLOW_PATH), "cosign verify")
    assert scripts, "no `cosign verify` step found"

    catch_alls = {".*", ".+", "^.*$", "(.*)", ""}
    for script in scripts:
        exact = _flag_value(script, "--certificate-identity")
        pattern = _flag_value(script, "--certificate-identity-regexp")
        assert exact is not None or pattern is not None, (
            "`cosign verify` must pass --certificate-identity or "
            "--certificate-identity-regexp; without one it is not keyless verification."
        )
        if pattern is not None:
            assert pattern not in catch_alls, (
                f"--certificate-identity-regexp={pattern!r} matches every signer. "
                "The gate must name this repository's workflow."
            )
            assert pattern.startswith("^") and pattern.endswith("$"), (
                f"--certificate-identity-regexp={pattern!r} is not anchored at both ends. "
                "cosign matches with Go's regexp.MatchString, which is a SUBSTRING "
                "match, so an unanchored pattern also accepts a padded identity."
            )
            assert re.escape(_REPOSITORY) in pattern or _REPOSITORY in pattern, (
                f"--certificate-identity-regexp={pattern!r} does not name {_REPOSITORY}."
            )
            assert r"github\.com" in pattern, (
                f"--certificate-identity-regexp={pattern!r} leaves the dots in the host "
                "unescaped, so they are wildcards and `githubXcom` matches too."
            )
            assert "deploy" in pattern, (
                f"--certificate-identity-regexp={pattern!r} does not name the deploy "
                "workflow, so a signature from any other workflow in this repository "
                "would satisfy it."
            )


def test_cosign_verify_identity_accepts_this_workflow_and_rejects_others() -> None:
    """The identity pattern is exercised, not merely inspected.

    Python's ``re.search`` reproduces cosign's matching semantics for patterns
    of this shape: sigstore-go's ``MatchesSAN`` calls Go's
    ``regexp.MatchString``, which is likewise an unanchored search over the
    SAN. (Go's ``$`` is end-of-text where Python's also matches before a final
    newline; no identity below carries one, and the anchor assertions above
    pin both ends explicitly.)
    """
    scripts = _run_scripts_containing(_parse(_WORKFLOW_PATH), "cosign verify")
    assert scripts, "no `cosign verify` step found"

    must_accept = [
        _IDENTITY(repo=_REPOSITORY, wf="deploy.yml", ref="refs/heads/main"),
        _IDENTITY(repo=_REPOSITORY, wf="deploy.yml", ref="refs/heads/worktree-deploy-gate"),
    ]
    must_reject = [
        # another repository, same workflow file name
        _IDENTITY(repo="attacker/postern", wf="deploy.yml", ref="refs/heads/main"),
        # another workflow in THIS repository
        _IDENTITY(repo=_REPOSITORY, wf="ci.yml", ref="refs/heads/main"),
        # a lookalike an unanchored pattern would wrongly admit: real identity
        # embedded in someone else's URL
        "https://evil.example/x?u="
        + _IDENTITY(repo=_REPOSITORY, wf="deploy.yml", ref="refs/heads/main"),
        # the same trick from the other end
        _IDENTITY(repo=_REPOSITORY, wf="deploy.yml", ref="refs/heads/main") + "@evil.example",
        # owner typosquat, which a pattern missing `^` would admit
        _IDENTITY(repo="notstefanocalabrese/postern", wf="deploy.yml", ref="refs/heads/main"),
        # repository typosquat
        _IDENTITY(repo="stefanocalabrese/postern-evil", wf="deploy.yml", ref="refs/heads/main"),
        # unescaped dots read as wildcards
        "https://githubXcom/stefanocalabrese/postern/Xgithub/workflows/deployXyml@refs/heads/main",
        # a tag ref rather than a branch ref
        _IDENTITY(repo=_REPOSITORY, wf="deploy.yml", ref="refs/tags/v1.0.0"),
        # an unrelated repository entirely
        _IDENTITY(repo="someone/anything", wf="whatever.yml", ref="refs/heads/main"),
    ]

    for script in scripts:
        pattern = _flag_value(script, "--certificate-identity-regexp")
        if pattern is None:
            continue  # an exact --certificate-identity is stricter still
        compiled = re.compile(pattern)
        for identity in must_accept:
            assert compiled.search(identity), (
                f"pattern {pattern!r} rejects the real signing identity {identity!r}. "
                "Every dispatch would fail at the verify step."
            )
        for identity in must_reject:
            assert not compiled.search(identity), (
                f"pattern {pattern!r} accepts {identity!r}, which is not this "
                "repository's deploy workflow on a branch ref."
            )


def test_cosign_verify_pins_the_oidc_issuer() -> None:
    """Every ``cosign verify`` pins the issuer, exactly rather than by regex.

    An identity check without an issuer check is defeated by any other OIDC
    provider. The regexp form of this flag was in use here and was itself
    unanchored with unescaped dots, so it accepted
    ``https://token.actions.githubusercontent.com.evil.example``.
    """
    scripts = _run_scripts_containing(_parse(_WORKFLOW_PATH), "cosign verify")
    assert scripts, "no `cosign verify` step found"

    for script in scripts:
        exact = _flag_value(script, "--certificate-oidc-issuer")
        assert exact == _OIDC_ISSUER, (
            f"`cosign verify` must pass --certificate-oidc-issuer={_OIDC_ISSUER!r} "
            f"(got {exact!r}). sigstore-go compares this one by string equality, "
            "so the exact flag is both stricter and simpler than the regexp form."
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
    """Both images are scanned by a Trivy step, not merely mentioned."""
    doc = _parse(_WORKFLOW_PATH)
    steps = _steps_using(doc, "aquasecurity/trivy-action")
    assert steps, (
        "Deploy workflow must scan images for vulnerabilities using Trivy. "
        "A prose mention of Trivy in a comment is not a scan."
    )
    scanned = " ".join(str(step.get("with", {}).get("image-ref", "")) for step in steps)
    for image in ("postern-api", "postern-confirm"):
        assert image in scanned, f"No Trivy step scans the {image} image."


def test_workflow_blocks_on_high_severity() -> None:
    """Each Trivy step itself blocks on HIGH/CRITICAL findings.

    Checked per step rather than per file. The old form was
    ``"exit-code" in content and '"1"' in content``, and the second half was
    satisfied by ``COSIGN_EXPERIMENTAL: "1"`` in a different job, so the
    assertion would have held with no ``exit-code`` value set at all.
    """
    steps = _steps_using(_parse(_WORKFLOW_PATH), "aquasecurity/trivy-action")
    assert steps, "no Trivy step found"

    for step in steps:
        with_block = step.get("with", {})
        assert str(with_block.get("exit-code", "")) == "1", (
            f'Trivy step {step.get("name")!r} must set exit-code: "1" so a finding '
            f"fails the job (got {with_block.get('exit-code')!r}). Without it Trivy "
            "prints a table and exits 0, and the gate reports success."
        )
        severities = {
            s.strip().upper() for s in str(with_block.get("severity", "")).split(",") if s.strip()
        }
        assert {"HIGH", "CRITICAL"} <= severities, (
            f"Trivy step {step.get('name')!r} must scan HIGH and CRITICAL "
            f"(got {with_block.get('severity')!r})."
        )


# ── Digest addressing ────────────────────────────────────────────


def test_no_step_addresses_an_image_by_tag() -> None:
    """Nothing consumes one of these images through a mutable pointer.

    Stated over the whole document rather than over the four steps that were
    wrong, so a step added later with a `:tag` reference fails here without
    anyone remembering to extend a list. Until 26 September 2026 both syft
    steps and both Trivy steps read `postern-<svc>:${{ github.sha }}` while
    cosign signed and ECS deployed `postern-<svc>@<digest>`, so the SBOM
    published and the scan gated on described an artifact that nothing
    downstream was pinned to.

    A tag is a pointer. Re-pushing it, which a second dispatch on the same
    commit does, moves every tag-addressed reader onto a different image
    while the signature keeps naming the old one.
    """
    doc = _parse(_WORKFLOW_PATH)

    offenders: list[str] = []
    digest_refs = 0
    for job, step in _steps(doc):
        label = str(step.get("name") or step.get("uses") or "<unnamed step>")
        for key, value in _step_scalars(step):
            if key in _TAG_ADDRESSED_KEYS:
                continue
            for match in _IMAGE_REF_RE.finditer(value):
                if match.group("sep") == "@":
                    digest_refs += 1
                    continue
                excerpt = value[match.start() : match.end() + 40].splitlines()[0]
                offenders.append(f"{job} / {label} / {key}: {excerpt}")

    assert not offenders, (
        "Every consumer of these images must address it by digest, not by tag:\n  "
        + "\n  ".join(offenders)
        + "\nUse `name@${{ steps.push-<svc>.outputs.digest }}` inside `build`, or "
        "`name@${{ needs.build.outputs.<svc>_digest }}` inside `deploy`."
    )
    assert digest_refs, (
        "No digest-addressed image reference found at all. Either the images "
        "were renamed and this test now checks nothing, or every reference "
        "was removed."
    )


def test_sbom_scan_and_signature_name_the_same_digest() -> None:
    """For each image, syft, Trivy and cosign resolve one identical digest.

    Addressing all three by digest is not enough on its own: three different
    digest expressions would still let them describe three different images.
    They must read the same push step's output.
    """
    doc = _parse(_WORKFLOW_PATH)

    for service in ("api", "confirm"):
        image = f"postern-{service}"
        expression = f"steps.push-{service}.outputs.digest"

        sboms = [
            str(step.get("with", {}).get("image", ""))
            for step in _steps_using(doc, "anchore/sbom-action")
            if image in str(step.get("with", {}).get("image", ""))
        ]
        scans = [
            str(step.get("with", {}).get("image-ref", ""))
            for step in _steps_using(doc, "aquasecurity/trivy-action")
            if image in str(step.get("with", {}).get("image-ref", ""))
        ]
        signatures = [
            script for script in _run_scripts_containing(doc, "cosign sign") if image in script
        ]

        for what, references in (("SBOM", sboms), ("Trivy scan", scans), ("signature", signatures)):
            assert references, f"No {what} step covers {image}."
            for reference in references:
                assert expression in reference, (
                    f"The {what} for {image} does not read {expression!r}, so the "
                    f"artifact it describes is not provably the one the other two "
                    f"steps cover. Got: {reference.strip()!r}"
                )


def test_every_digest_reference_follows_the_push_step_that_produces_it() -> None:
    """A `steps.<id>.outputs.digest` reference sits after the step it names.

    Referencing a step that has not run yet is not an error in Actions, it is
    an empty string, which turns `name@` into a malformed reference and would
    surface as a registry error rather than as the ordering bug it is.
    """
    doc = _parse(_WORKFLOW_PATH)

    for job_name, job in doc["jobs"].items():
        steps = job.get("steps", [])
        positions = {str(step["id"]): index for index, step in enumerate(steps) if "id" in step}
        for index, step in enumerate(steps):
            label = str(step.get("name") or step.get("uses") or f"step {index}")
            for _, value in _step_scalars(step):
                for step_id in _DIGEST_EXPR_RE.findall(value):
                    assert step_id in positions, (
                        f"{job_name} / {label} reads steps.{step_id}.outputs.digest, "
                        f"but no step in that job carries id {step_id!r}. The "
                        "expression resolves to an empty string."
                    )
                    assert positions[step_id] < index, (
                        f"{job_name} / {label} reads steps.{step_id}.outputs.digest "
                        "before that step runs, so the digest is empty there."
                    )


def test_no_digest_reference_doubles_the_sha256_prefix() -> None:
    """The workflow writes `name@<expr>`, never `name@sha256:<expr>`.

    `docker/build-push-action` sets its `digest` output from buildkit's
    `containerimage.digest`, which already reads `sha256:<64 hex>`. Writing
    the prefix again produces `name@sha256:sha256:...`, which no registry
    resolves.
    """
    content = _read_workflow()
    assert "@sha256:${{" not in content, (
        "A digest expression is prefixed with `sha256:` in the workflow. The "
        "`digest` output carries that prefix already, so this yields "
        "`name@sha256:sha256:...`."
    )


# ── Action pinning ───────────────────────────────────────────────


def test_every_action_is_pinned_to_a_full_commit_sha() -> None:
    """No `uses:` in either workflow rides a mutable ref.

    ``aquasecurity/trivy-action@v0`` sat here until 25 September 2026 and
    resolved to nothing at all, so the step it belonged to could never run.
    A tag that does resolve is the worse case: it can be repointed at other
    code, and these jobs hold ECR push credentials and an assumed AWS role.
    """
    for path in (_WORKFLOW_PATH, _CI_WORKFLOW_PATH):
        doc = _parse(path)
        for job, step in _steps(doc):
            uses = step.get("uses")
            if uses is None:
                continue
            assert "@" in str(uses), f"{path.name}: `uses: {uses}` carries no ref at all."
            action, _, ref = str(uses).partition("@")
            assert _SHA_PIN_RE.match(ref), (
                f"{path.name} job {job!r}: `uses: {action}@{ref}` is not pinned to a "
                "full 40-character commit SHA. A tag or branch can be repointed, and "
                "these jobs hold AWS credentials."
            )


def test_every_sha_pin_names_its_version_in_a_trailing_comment() -> None:
    """Each pin carries `# vX.Y.Z`, which is what dependabot bumps.

    Read from the raw text, because a comment is not in the parsed document.
    """
    for path in (_WORKFLOW_PATH, _CI_WORKFLOW_PATH):
        text = path.read_text()
        for match in _PINNED_USES_LINE_RE.finditer(text):
            action = match.group("action")
            comment = match.group("comment")
            assert re.search(r"#\s*v?\d+\.\d+", comment), (
                f"{path.name}: `uses: {action}@...` has no trailing version comment. "
                "The SHA alone is unreadable and dependabot matches on the comment."
            )


# ── Structural gates ─────────────────────────────────────────────


def test_workflow_has_build_and_deploy_stages() -> None:
    """The workflow has separate build and deploy jobs."""
    jobs = _parse(_WORKFLOW_PATH)["jobs"]
    assert "build" in jobs, "Deploy workflow must have a 'build' job."
    assert "deploy" in jobs, "Deploy workflow must have a 'deploy' job."


def test_deploy_requires_environment_approval() -> None:
    """The deploy job uses GitHub Environments for manual approval."""
    deploy = _parse(_WORKFLOW_PATH)["jobs"]["deploy"]
    assert deploy.get("environment"), (
        "Deploy job must use GitHub Environments for manual approval gates. "
        "Production deploys require human sign-off."
    )


def test_workflow_dispatch_only() -> None:
    """Both workflows trigger on dispatch and on nothing else.

    The owner has no billed Actions minutes, so an automatic trigger costs
    money and sends a notification on every push. The old form read only
    ``content[:500]`` and looked for ``push:`` and ``pull_request:``, which
    left ``schedule:``, ``repository_dispatch:`` and anything declared past
    the 500th character unchecked, and covered deploy.yml alone.
    """
    for path in (_WORKFLOW_PATH, _CI_WORKFLOW_PATH):
        triggers = _triggers(_parse(path))
        assert set(triggers) == {"workflow_dispatch"}, (
            f"{path.name} must trigger on workflow_dispatch and nothing else "
            f"(found {sorted(str(k) for k in triggers)}). Any automatic trigger "
            "bills the owner for minutes he does not have."
        )


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


def test_both_workflow_files_are_valid_yaml() -> None:
    """Both workflows parse, so every assertion above sees a real document."""
    for path in (_WORKFLOW_PATH, _CI_WORKFLOW_PATH):
        doc = _parse(path)
        assert "jobs" in doc, f"{path.name} declares no jobs."

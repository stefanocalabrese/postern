# 0011: Deploy pipeline — cosign, SBOM, Trivy (ZT-3)

**Date:** 2026-09-21

## Question

ZT-3 requires "verify cosign signatures at deploy time as a hard gate" and
"verify SBOM presence and scan results." The zero-trust plan §6.1 lists
"Cosign signature + SBOM verification at deploy" as a blocking CI gate.
Digest drift detection (gate 7a) already runs in `make ci`. What does the
full deploy pipeline look like, and how do cosign signing + verification,
SBOM generation, and vulnerability scanning fit together?

## Decision

Adopt a two-stage GitHub Actions workflow (`deploy.yml`) that runs on
`workflow_dispatch` (same model as `ci.yml` — no automatic triggers to avoid
billed minutes on a private repo):

1. **Build stage** — runs `make ci` (all six local gates), builds both Docker
   images (`api`, `confirm`) with Buildx, generates SBOMs (syft → SPDX),
   scans images for vulnerabilities (Trivy), signs images with cosign
   (keyless, OIDC from GitHub), and pushes to ECR.

2. **Deploy stage** — runs only on `environment: production` (manual approval
   gate), verifies the cosign signature against Sigstore transparency log,
   and deploys to ECS.

### Cosign signing — keyless (OIDC)

Keyless signing uses GitHub's OIDC tokens to obtain a short-lived signing
certificate from the Sigstore Fulcio CA, then records the signature in the
Rekor transparency log. No static keys to rotate, no `cosign key` management.

```
Image pushed to ECR → cosign sign --yes (OIDC) → signature recorded in Rekor
```

The deploy stage verifies by checking the Sigstore transparency log (no local
key needed):

```
cosign verify --certificate-identity-regexp=".*" \
              --certificate-oidc-issuer-regexp="https://token.actions.githubusercontent.com" \
              --rekor-url=https://rekor.sigstore.dev \
              <ecr-repo>/<image>:<digest>
```

### SBOM — syft → SPDX

`syft` generates an SPDX 2.3 JSON SBOM for each image:

```
syft <image> --output spdx-json > sbom.spdx.json
```

The SBOM is uploaded as a workflow artifact for audit retention. The deploy
stage checks that the SBOM exists before proceeding (hard gate).

### Vulnerability scanning — Trivy

Trivy scans the image against NVD + GitHub Advisory Database:

```
trivy image --severity HIGH,CRITICAL --exit-code 1 <image>
```

Failures block the build. `LOW` and `MEDIUM` are reported but do not block —
they are tracked for trend analysis.

### ECR push with digest pinning

Images are pushed to ECR using their **sha256 digest** as the tag (not mutable
tags like `latest` or `main`). This mirrors the Dockerfile's own digest-pinning
approach and makes every image address immutable:

```
aws ecr batch-get-image --repository-name postern-api --image-ids imageDigest=<digest>
```

The digest is the only reference used in ECS task definitions — no tag-based
resolution.

### Environment separation

| Stage | `api` | `confirm` | Trigger |
|---|---|---|---|
| Build | Always | Always | `workflow_dispatch` |
| Deploy (staging) | Yes | Yes | Manual approval (`environment: staging`) |
| Deploy (production) | Yes | Yes | Manual approval (`environment: production`) |

Staging and production are separate GitHub Environments with required reviewers.
The workflow file itself is the same; environment gates control who can proceed.

## Why not other approaches?

### Static cosign key (KMS-backed)

KMS-backed signing works but requires managing a long-lived key ARN, rotating
it periodically, and granting the pipeline IAM permission to use it. Keyless
OIDC eliminates all of that — GitHub handles the identity, Sigstore handles
the CA. For a regulated operator this is acceptable because the transparency
log provides the same audit trail, and the certificate identity is bound to
the GitHub repository + branch.

### Docker BuildKit cache to ECR

BuildKit can push directly to ECR, but we need SBOM generation and Trivy
scanning *between* build and push. A two-step approach (build locally → scan
→ sign → push) is simpler than trying to orchestrate everything in a single
BuildKit invocation.

### Inline cosign verification in the same workflow

Verification happens in a **separate** deploy stage, not inline with signing.
This models the real-world scenario: an image is built and signed in one
pipeline run, then verified at deploy time (potentially hours or days later)
by a different pipeline run. The verification step is the actual ZT-3 gate —
it proves that the image being deployed was signed by this repository.

## Implementation

- `.github/workflows/deploy.yml` — the full pipeline (build + deploy stages)
- `tests/test_zt3_deploy_pipeline.py` — validates the workflow file contains
  all required ZT-3 gates (cosign sign, cosign verify, syft, trivy)
- `tests/test_zt3_digest_drift.py` — existing digest drift test (unchanged)

## Acceptance

- A deliberately unsigned image fails the deploy stage's cosign verification.
- An image with a HIGH/CRITICAL vulnerability fails Trivy scanning.
- A missing SBOM blocks deployment.
- Digest drift in the Dockerfile fails `make ci` (existing gate 7a).

## Open questions

1. **SBOM retention policy** — how long to keep SBOM artifacts? (Suggested:
   7 years for regulated operator compliance.)
2. **Trivy ignore file** — should certain CVEs be ignored? (e.g., known
   false positives in base images.) Needs platform team input.
3. **ECS deployment strategy** — blue/green vs rolling? (Not in scope for
   this decision; handoff §12.4 leaves it to the platform team.)

## Next steps — Terraform repo (gate 5)

This repo contains the deploy workflow and its tests. The **Terraform repo**
owns everything below. These are the concrete items to implement there:

### 1. Infrastructure (Terraform)

- **ECR repositories** — one per image (`postern-api`, `postern-confirm`) with
  lifecycle rules (retain last N images, delete untagged).
- **ECS cluster + services** — Fargate tasks for `api` and `confirm`, each
  with its own task definition referencing the image by **sha256 digest** (not
  tag). Task definitions are updated via the deploy workflow's `aws ecs
  update-service --force-new-deployment`.
- **Task roles** — separate IAM roles for `api` (read) and `confirm` (write).
  The read role must **not** be able to assume the write role or access its
  Vault path. This is the IAM policy test (gate 5).
- **VPC / subnets** — private subnets for ECS, NAT Gateway (or egress deny
  per ZT-8), PrivateLink endpoint to the backend Istio gateway.
- **SSM Parameter Store** — publish ECR URIs, cluster name, service names,
  subnet IDs, secret ARNs under `/postern/<env>/` for cross-repo contract
  (handoff §10.27).

### 2. AWS-level tests (in Terraform repo)

- **IAM policy test** — assert the read task role cannot assume the write
  role or read its Vault path. Use `terraform plan` + `aws_iam_policy_document`
  data sources, or an inline Python test that loads the generated policies.
- **ECS task definition validation** — assert each task references images by
  digest, not tag. Assert `networkMode = awsvpc` (no host networking).
  Assert `readonlyRootFilesystem = true`.
- **Security group validation** — assert the read SG cannot reach write
  backend endpoints; assert no `0.0.0.0/0` egress except to known AWS
  endpoints (via VPC endpoints).
- **Cosign verification integration test** — a CI step that builds an image,
  pushes it unsigned to ECR, then runs the deploy workflow's cosign verify
  step against it and asserts failure. This is the "deliberately unsigned
  image fails" acceptance test from ZT-3.

### 3. GitHub configuration (manual, one-time)

- Create two **GitHub Environments** (`staging`, `production`) with required
  reviewers. The deploy workflow's `environment:` field gates on these.
- Add repository secrets: `AWS_ROLE_ARN` (OIDC role for the pipeline),
  `AWS_ECR_REGISTRY` (ECR URI).

### 4. Runtime threat detection (GuardDuty)

- Enable GuardDuty Runtime Monitoring on Fargate tasks. This requires the
  EKS/Fargate agent and is left for platform team to provision.

**Status:** deploy workflow + tests are ready. The Terraform repo needs the
items above to make this a live deploy pipeline.

## Amended 2 October 2026: Cosign v3 semantics

The deploy workflow was upgraded from cosign v2.5.2 to v3.0.6 on 2 October 2026. Under cosign v3:

- `cosign sign --yes` writes a Sigstore bundle in the OCI Image 1.1 referrer format, containing all verification material (certificate, timestamp proof, transparency log entry).
- When the image carries a Sigstore bundle, `cosign verify` does not build a Rekor client from `--rekor-url` (see https://github.com/sigstore/cosign/blob/v3.0.6/cmd/cosign/cli/verify/common.go line 133: `if !ignoreTlog && !co.NewBundleFormat && rekorURL != "" { co.RekorClient, err = rekor.NewClient(rekorURL) ...}`, so the client is built only when NOT using the new bundle format). Instead, it verifies the bundle's signatures against the Sigstore TUF trusted root, using the transparency log entry embedded in the bundle.
- The `--rekor-url` flag is retained in the workflow for backward compatibility but is not used when the bundle format is present (the new default in v3).

No workflow steps changed: the `cosign sign` invocation uses `--yes` (unchanged), and the `cosign verify` steps retain `--rekor-url=https://rekor.sigstore.dev` (unchanged). The behavioral difference is that v3 defaults to the bundle format, which contains all verification material inline.

## Amended 3 October 2026: the cosign v3 claims, measured

The 2 October amendment was read from cosign's source. `tests/test_cosign_v3_local.py` runs cosign v3.0.6 (image digest `sha256:de9c65609e6bde17e6b48de485ee788407c9502fa08b8f4459f595b21f56cd00`) against zot v2.1.21 (`sha256:c8090a5e34627e306b9464f5e7c69ad8cdb5948d4476e9cde0eb1a8e2181e3fa`), a registry that serves the OCI 1.1 referrers API, on a docker network with no external route. It signs and verifies with a throwaway KEY, because keyless signing needs a real OIDC token. Measured:

- `cosign sign` stores the signature as a referrer of the image digest, `artifactType` `application/vnd.dev.sigstore.bundle.v0.3+json`. No `sha256-<hex>.sig` tag and no `sha256-<hex>` fallback tag exist. Confirmed.
- `cosign verify` with the signing key passes; with another key it fails; on a second image nobody signed it fails with "no signatures found". Confirmed. The unsigned-image control in this record's Acceptance section holds for the verify mechanics.
- `--rekor-url=https://rekor.sigstore.dev` is accepted by a bundle-format verify (exit 0). That alone does not show it is unused, because the offline run needs `--insecure-ignore-tlog`. The evidence for "unused" is a by-hand run with the TUF mirror reachable and no `--insecure-ignore-tlog`: a bogus `--rekor-url=https://rekor.invalid.example`, the real URL and no flag all returned the identical error ("failed to verify log inclusion ... 0 < 1"), none a connection error. With `--new-bundle-format=false`, with no flag, a bogus flag or the real one, the first network step is the TUF fetch of Rekor's public keys ("getting rekor public keys"); the keys come from TUF whatever the flag says. That the legacy path builds a Rekor client from `--rekor-url` is read from cosign v3.0.6 `cmd/cosign/cli/verify/common.go` line 133, not measured.
- Correction to the 2 October text: a bundle verify without `--insecure-ignore-tlog` does reach the network, to `tuf-repo-cdn.sigstore.dev` for the trusted root, and fails with "trusted root is required when using new bundle format" when it cannot. It does not reach Rekor. The deploy job needs egress to that host.
- Not caused by this repository, but found: a registry that lacks the referrers API makes cosign fall back to the `sha256-<hex>` tag schema (distribution 3.1.2, `registry:3`, answers 404 on `/v2/<name>/referrers/<digest>`). Whether ECR serves the referrers API, and whether cosign's fallback is what an ECR run would use, is not measured here.
- Keyed signing in v3.0.6 rejects `--tlog-upload=false` with the default signing config, and the default config is fetched from TUF, so the local test signs with an empty signing config. Its signature carries no transparency-log entry or timestamp.

- Defect found while reading the deploy job (reasoned, not run: no AWS here): it called `configure-aws-credentials` but never logged in to ECR, and cosign reads registry credentials only from the Docker config keychain by default, so each `cosign verify` would have failed with an auth error that the `::error::` text reports as an unsigned or tampered image. The same pinned `aws-actions/amazon-ecr-login` step the build job uses now precedes the verify steps, and `tests/test_zt3_deploy_pipeline.py` asserts every job that runs cosign has an earlier ECR login.

Still unmeasured: keyless signing (Fulcio certificate, GitHub OIDC), `--certificate-identity-regexp` and `--certificate-oidc-issuer` against a real certificate, Rekor inclusion proof, ECR.

## Amended 3 October 2026: SBOM artifact retention

Open question 1 (SBOM retention policy) is now decided: SBOM artifacts are retained for 90 days, the documented maximum of the `actions/upload-artifact` action (README: "The retention period must be between 1 and 90 inclusive"). The suggested 7 years is not met by Actions artifacts; operators with a longer retention requirement must copy the SBOM to their own storage (S3, GCS, or equivalent) with a lifecycle rule matching their compliance obligation. The earlier workflow value of 2555 (approximately 7 years) exceeded the action's documented range; what GitHub Actions does with an out-of-range value is not established, and operators should not rely on it.

## References

- Zero-trust plan §ZT-3, §6.1 (gate 7)
- Handoff §12.4 (supply-chain requirements), §10.26 (SBOM format, signing)
- Cosign keyless signing: https://docs.sigstore.dev/cosign/signing/
- syft SBOM generation: https://github.com/anchore/syft
- Trivy vulnerability scanning: https://github.com/aquasecurity/trivy
- Cosign v3.0.1 release notes: https://github.com/sigstore/cosign/releases/tag/v3.0.1

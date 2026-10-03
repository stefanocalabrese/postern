"""Measure the cosign v3 sign and verify mechanics against a local OCI 1.1 registry.

WHY THIS FILE EXISTS. Decision record 0011's 2 October 2026 amendment and
CLAUDE.md gate 7b state what cosign v3.0.6 does on the deploy path: `cosign
sign --yes` writes a Sigstore bundle as an OCI 1.1 referrer, `cosign verify`
finds it, and `--rekor-url` is not used when the image carries a bundle. Those
sentences were read out of cosign's source. This file runs the binary.

WHAT RUNS. A registry that implements the OCI 1.1 referrers API (zot, pinned
by digest; `registry:3`, distribution 3.1.2, was run by hand on 3 October
2026 and answers 404 on `/v2/<name>/referrers/<digest>`, so cosign falls back to
the `sha256-<digest>` tag schema there), two throwaway images pushed to it,
and cosign v3.0.6 from the official `ghcr.io/sigstore/cosign/cosign` image,
pinned by index digest. Every cosign call runs in a container on a docker
network created with `internal=True`, which has no route off the host, so a
call that needed Rekor, Fulcio or the TUF mirror would fail by name
resolution, not by luck.

WHAT THIS DOES NOT PROVE, AND WHY. Keyless signing needs a real OIDC token
and a Fulcio certificate, which cannot be minted locally. These tests sign
and verify KEYED, with a throwaway key pair. The differences from
`.github/workflows/deploy.yml`:

* sign: `--key cosign.key` is added. `COSIGN_EXPERIMENTAL=1` is still set (a
  no-op since cosign v2). `--allow-http-registry` is added because the local
  registry speaks plain HTTP on a non-loopback name. `--signing-config
  signing-config.json` is added, naming no Fulcio, Rekor, OIDC or TSA
  service: cosign v3.0.6 rejects `--tlog-upload=false` together with the
  default TUF-provided signing config, and a plain `cosign sign --key`
  on a host without a route to `tuf-repo-cdn.sigstore.dev` fails fetching
  that config. So the signature here carries NO transparency-log entry and
  NO timestamp, which the workflow's signature does.
* verify: `--key cosign.pub` replaces `--certificate-identity-regexp` and
  `--certificate-oidc-issuer`, which only apply to a Fulcio certificate.
  `--rekor-url=https://rekor.sigstore.dev` is passed exactly as the workflow
  passes it where a test says so. `--insecure-ignore-tlog` is added because
  there is no log entry to verify; it has no counterpart in the workflow.
  Tests (a) to (d) therefore show the referrer mechanics and the pass/fail
  behaviour of verify; they say nothing about identity matching or about
  transparency-log inclusion.
* One claim is NOT settled offline. "`--rekor-url` is ignored when the image
  carries a bundle" needs a verify that does not pass `--insecure-ignore-tlog`
  and has the TUF mirror reachable. That was run once by hand on 3 October
  2026 (not in this file, because it needs the internet): on the same
  keyed, log-less bundle, `verify --key ... --rekor-url=https://rekor.invalid.example`,
  `--rekor-url=https://rekor.sigstore.dev` and no `--rekor-url` all failed with
  the identical message `failed to verify log inclusion: not enough verified
  log entries from transparency log: 0 < 1`, and none reported a connection
  error to the Rekor URL. A bogus host producing the same error as no flag is
  the evidence the flag is not consulted in bundle mode.
* ECR is not involved. Whether ECR serves the referrers API cosign relies on
  is a fact about AWS, not about this binary.
"""

from __future__ import annotations

import io
import json
import socket
import tarfile
import time
import urllib.error
import urllib.request
import uuid
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

import docker
import pytest
import requests
from docker.errors import APIError, DockerException, ImageNotFound
from docker.models.containers import Container
from docker.models.networks import Network

#: cosign v3.0.6, the version `sigstore/cosign-installer` v4.1.2 installs by
#: default. Index digest of `ghcr.io/sigstore/cosign/cosign:v3.0.6`, resolved
#: 3 October 2026 with `docker buildx imagetools inspect`; the manifests in it
#: are linux/amd64 and linux/arm64/v8.
COSIGN_IMAGE = (
    "ghcr.io/sigstore/cosign/cosign@sha256:"
    "de9c65609e6bde17e6b48de485ee788407c9502fa08b8f4459f595b21f56cd00"
)

#: zot-minimal v2.1.21, an OCI-conformant registry that serves the 1.1
#: referrers API. Index digest resolved 3 October 2026.
REGISTRY_IMAGE = (
    "ghcr.io/project-zot/zot-minimal@sha256:"
    "c8090a5e34627e306b9464f5e7c69ad8cdb5948d4476e9cde0eb1a8e2181e3fa"
)

REGISTRY_ALIAS = "registry.test"
REGISTRY_PORT = 5000
KEY_PASSWORD = "throwaway"  # noqa: S105 - protects a key that lives for one test run

#: Media type the Sigstore bundle spec gives a bundle stored as an OCI artifact.
BUNDLE_ARTIFACT_TYPE_PREFIX = "application/vnd.dev.sigstore.bundle"

#: See the module docstring for why each flag differs from deploy.yml.
SIGN_FLAGS = ["--yes", "--signing-config", "signing-config.json", "--allow-http-registry"]
VERIFY_FLAGS = ["--insecure-ignore-tlog", "--allow-http-registry"]


@dataclass(frozen=True)
class Run:
    rc: int
    out: str


@dataclass(frozen=True)
class Lab:
    client: docker.DockerClient
    net: Network
    base_url: str  # registry as seen from the host
    key_volume: str
    other_key_volume: str
    signed: str  # sha256:... of the image that carries a signature
    unsigned: str  # sha256:... of a second image nobody signed

    def ref(self, digest: str) -> str:
        return f"{REGISTRY_ALIAS}:{REGISTRY_PORT}/lab/img@{digest}"

    def cosign(
        self,
        args: list[str],
        *,
        volume: str | None = None,
        extra_env: dict[str, str] | None = None,
    ) -> Run:
        env = {"COSIGN_PASSWORD": KEY_PASSWORD, "COSIGN_EXPERIMENTAL": "1"}
        env.update(extra_env or {})
        box = self.client.containers.run(
            COSIGN_IMAGE,
            args,
            detach=True,
            network=self.net.name,
            environment=env,
            volumes={volume or self.key_volume: {"bind": "/k", "mode": "rw"}},
            working_dir="/k",
            # A fresh named volume is root-owned and the image's default user
            # is not root; both ran into "permission denied" on the key file.
            user="0",
        )
        try:
            rc = box.wait(timeout=120)["StatusCode"]
            out = box.logs(stdout=True, stderr=True).decode(errors="replace")
        finally:
            box.remove(force=True)
        return Run(rc, out)

    def get(self, path: str, accept: str = "*/*") -> tuple[int, bytes]:
        req = urllib.request.Request(  # noqa: S310 - fixed http URL to the local registry
            f"{self.base_url}{path}", headers={"Accept": accept}
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:  # noqa: S310
                return resp.status, resp.read()
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read()

    def referrers(self, digest: str) -> list[dict[str, object]]:
        status, body = self.get(f"/v2/lab/img/referrers/{digest}")
        assert status == 200, (status, body)
        manifests: list[dict[str, object]] = json.loads(body)["manifests"]
        return manifests

    def tags(self) -> list[str]:
        status, body = self.get("/v2/lab/img/tags/list")
        assert status == 200, (status, body)
        return json.loads(body)["tags"] or []


def _image_tar(payload: bytes) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        dockerfile = b"FROM scratch\nCOPY payload /payload\n"
        for name, data in (("Dockerfile", dockerfile), ("payload", payload)):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def _push(client: docker.DockerClient, base_url: str, payload: bytes, tag: str) -> str:
    """Build a one-file FROM-scratch image, push it, return the registry's digest."""
    # The daemon allows plain HTTP for 127.0.0.0/8 only. The name `localhost`
    # can resolve to ::1, where the published port is not bound, and then the
    # push times out on an HTTPS probe.
    repo = f"{base_url.removeprefix('http://')}/lab/img"
    client.images.build(
        fileobj=io.BytesIO(_image_tar(payload)), custom_context=True, tag=f"{repo}:{tag}"
    )
    # The daemon decides HTTP-versus-HTTPS from one probe, and a probe sent in
    # the first second after the container starts has been refused; retry.
    for attempt in range(6):
        pushed = client.images.push(repo, tag=tag)
        if '"error"' not in pushed:
            break
        time.sleep(1 + attempt)
    assert '"error"' not in pushed, pushed
    req = urllib.request.Request(  # noqa: S310
        f"{base_url}/v2/lab/img/manifests/{tag}",
        method="HEAD",
        headers={
            "Accept": "application/vnd.oci.image.manifest.v1+json, "
            "application/vnd.oci.image.index.v1+json, "
            "application/vnd.docker.distribution.manifest.v2+json"
        },
    )
    with urllib.request.urlopen(req, timeout=10) as resp:  # noqa: S310
        digest = resp.headers["Docker-Content-Digest"]
    client.images.remove(f"{repo}:{tag}", force=True)
    return str(digest)


def _ensure_image(client: docker.DockerClient, image: str) -> None:
    """Use a cached copy of a pinned image, else pull it.

    A pull that cannot reach ghcr.io skips the module with a reason. A pull
    that succeeds but lands on a different digest than the pin is an error,
    never a skip: that is the one outcome this pin exists to catch.
    """
    try:
        client.images.get(image)
        return
    except ImageNotFound:
        pass
    except DockerException:
        pass
    try:
        pulled = client.images.pull(image)
    except (APIError, ImageNotFound, requests.exceptions.RequestException) as exc:
        pytest.skip(f"cannot pull pinned image {image} (registry unreachable?): {exc}")
    digest = image.split("@", 1)[1]
    repo_digests = [str(d) for d in (pulled.attrs.get("RepoDigests") or [])]
    index_digest = digest in "".join(repo_digests)
    assert index_digest or pulled.id == digest, (
        f"pulled {image} but the daemon reports {repo_digests} / {pulled.id}"
    )


def _free_port() -> int:
    """Pick the host port ourselves.

    A port the daemon assigns (`None`) made the daemon's own push to
    `127.0.0.1:<port>` fail with a refused HTTPS probe on this machine, while
    the same registry on an explicitly requested port pushed fine (measured
    3 October 2026, Docker 29.8.1, 2 of 2 runs each way).
    """
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


@pytest.fixture(scope="module")
def lab() -> Iterator[Lab]:
    try:
        client = docker.from_env()
        client.ping()
    except DockerException as exc:
        pytest.skip(f"Docker is not reachable, skipping cosign v3 measurement: {exc}")

    prefix = f"postern-cosign-{uuid.uuid4().hex[:8]}"
    created_containers: list[Container] = []
    volumes = [f"{prefix}-keys", f"{prefix}-other-keys"]
    net: Network | None = None
    try:
        for image in (COSIGN_IMAGE, REGISTRY_IMAGE):
            _ensure_image(client, image)

        # Cosign containers join only this network: no route off the host.
        net = client.networks.create(f"{prefix}-net", driver="bridge", internal=True)
        # The registry also sits on the default bridge, because a published
        # port does not work from an internal network.
        registry = client.containers.run(
            REGISTRY_IMAGE,
            detach=True,
            name=f"{prefix}-registry",
            ports={f"{REGISTRY_PORT}/tcp": ("127.0.0.1", _free_port())},
        )
        created_containers.append(registry)
        registry.reload()
        published: Any = registry.ports  # the stub types it as a list; the API returns a dict
        host_port = published[f"{REGISTRY_PORT}/tcp"][0]["HostPort"]
        base_url = f"http://127.0.0.1:{host_port}"

        deadline = time.monotonic() + 30
        while True:
            try:
                with urllib.request.urlopen(f"{base_url}/v2/", timeout=2):  # noqa: S310
                    break
            except (urllib.error.URLError, ConnectionError, OSError):
                if time.monotonic() > deadline:
                    pytest.fail("registry did not come up within 30 s")
                time.sleep(0.3)

        signed = _push(client, base_url, b"signed image payload\n", "signed")
        unsigned = _push(client, base_url, b"a different, unsigned payload\n", "unsigned")

        # Attached only after the pushes: connecting the registry to an
        # internal network first made the daemon's push to the published port
        # fail with "connection refused" (measured 3 October 2026).
        net.connect(registry, aliases=[REGISTRY_ALIAS])
        for volume in volumes:
            client.volumes.create(volume)
        built = Lab(client, net, base_url, volumes[0], volumes[1], signed, unsigned)
        for volume in volumes:
            run = built.cosign(["generate-key-pair"], volume=volume)
            assert run.rc == 0, run.out
        # A signing config naming no Fulcio, Rekor, OIDC or TSA service.
        run = built.cosign(
            ["signing-config", "create", "--no-default-fulcio", "--no-default-oidc"]
            + ["--no-default-rekor", "--no-default-tsa", "--out", "signing-config.json"]
        )
        assert run.rc == 0, run.out
        run = built.cosign([*["sign", "--key", "cosign.key"], *SIGN_FLAGS, built.ref(signed)])
        assert run.rc == 0, run.out
        yield built
    finally:
        for box in created_containers:
            try:
                box.remove(force=True)
            except DockerException:
                pass
        if net is not None:
            try:
                net.remove()
            except DockerException:
                pass
        for volume in volumes:
            try:
                client.volumes.get(volume).remove(force=True)
            except DockerException:
                pass


def test_signature_is_an_oci_1_1_referrer_not_a_legacy_tag(lab: Lab) -> None:
    """(a) The signature is a referrer of the image, typed as a Sigstore bundle."""
    manifests = lab.referrers(lab.signed)
    assert len(manifests) == 1, manifests
    assert str(manifests[0]["artifactType"]).startswith(BUNDLE_ARTIFACT_TYPE_PREFIX), manifests

    # No legacy `sha256-<hex>.sig` tag, and no `sha256-<hex>` referrers-tag
    # fallback either: the registry served the real API, so cosign used it.
    hexdigest = lab.signed.removeprefix("sha256:")
    assert f"sha256-{hexdigest}.sig" not in lab.tags()
    assert f"sha256-{hexdigest}" not in lab.tags()
    assert sorted(lab.tags()) == ["signed", "unsigned"]

    # The unsigned image has no referrers at all.
    assert lab.referrers(lab.unsigned) == []


def test_verify_with_the_signing_key_succeeds(lab: Lab) -> None:
    """(b) cosign verify finds the bundle through the referrers API."""
    run = lab.cosign(["verify", "--key", "cosign.pub", *VERIFY_FLAGS, lab.ref(lab.signed)])
    assert run.rc == 0, run.out
    assert lab.signed in run.out


def test_verify_with_a_different_key_fails(lab: Lab) -> None:
    """(c) A key that did not sign the image does not verify it."""
    run = lab.cosign(
        ["verify", "--key", "cosign.pub", *VERIFY_FLAGS, lab.ref(lab.signed)],
        volume=lab.other_key_volume,
    )
    assert run.rc == 1, run.out
    assert "accepted signatures do not match threshold" in run.out, run.out


def test_unsigned_image_fails_verification(lab: Lab) -> None:
    """(d) The repo's documented control: an unsigned image fails the verify stage."""
    run = lab.cosign(["verify", "--key", "cosign.pub", *VERIFY_FLAGS, lab.ref(lab.unsigned)])
    assert run.rc == 10, run.out
    assert "no signatures found" in run.out, run.out


def test_rekor_url_flag_is_accepted_by_bundle_verify(lab: Lab) -> None:
    """(e) The workflow's exact `--rekor-url` flag is accepted and exit is 0.

    Offline, with `--insecure-ignore-tlog` (see the module docstring), so this
    shows acceptance of the flag and nothing about whether it is consulted.
    """
    run = lab.cosign(
        [
            "verify",
            "--key",
            "cosign.pub",
            "--rekor-url=https://rekor.sigstore.dev",
            *VERIFY_FLAGS,
            lab.ref(lab.signed),
        ]
    )
    assert run.rc == 0, run.out


def test_bundle_verify_needs_the_tuf_trusted_root_unless_the_log_is_ignored(lab: Lab) -> None:
    """(f) A deploy-path property the workflow inherits: bundle verify reaches TUF.

    Without `--insecure-ignore-tlog`, cosign v3 verifying a bundle fetches the
    Sigstore trusted root from `tuf-repo-cdn.sigstore.dev` and refuses to go on
    without it. On the deploy job this is a new network dependency beside the
    ECR pull; GitHub-hosted runners have it. `--rekor-url` does not change it.
    """
    for extra in ([], ["--rekor-url=https://rekor.sigstore.dev"]):
        run = lab.cosign(
            ["verify", "--key", "cosign.pub", *extra, "--allow-http-registry", lab.ref(lab.signed)]
        )
        assert run.rc != 0, run.out
        assert "tuf-repo-cdn.sigstore.dev" in run.out, run.out
        assert "trusted root is required when using new bundle format" in run.out, run.out


def test_legacy_format_verify_fetches_rekor_keys_from_tuf(lab: Lab) -> None:
    """(g) With the bundle format off, verify's first network step is TUF for Rekor's keys.

    Measured: with no flag, with a bogus `--rekor-url` and with the real one,
    the failure is the same, at client setup and before the image is looked
    at: `getting rekor public keys`. The keys come from TUF whatever the
    flag says. That the legacy path builds a Rekor client from `--rekor-url`
    is read from cosign v3.0.6 `cmd/cosign/cli/verify/common.go` line 133,
    not measured here.
    """
    for extra in (
        [],
        ["--rekor-url=https://rekor.invalid.example"],
        ["--rekor-url=https://rekor.sigstore.dev"],
    ):
        run = lab.cosign(
            [
                "verify",
                "--key",
                "cosign.pub",
                "--new-bundle-format=false",
                *extra,
                "--allow-http-registry",
                lab.ref(lab.signed),
            ]
        )
        assert run.rc != 0, run.out
        assert "getting rekor public keys" in run.out, run.out
        assert "tuf-repo-cdn.sigstore.dev" in run.out, run.out

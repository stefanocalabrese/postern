"""ZT-8 — No hardcoded external endpoints in application code.

Verifies that the application has no hardcoded HTTP(S) URLs pointing to
external services. Every URL must be either:

1. An internal default (``*.internal``, ``localhost``, ``backend.test``,
   ``postern-local-dev.invalid``, or a stub URL).
2. Read from an environment variable (``os.environ[...]`` or
   ``os.environ.get(...)``).

This is the code-level half of ZT-8's egress enumeration. The full
enumeration (including infrastructure) is in ``docs/decisions/0009-egress-analysis.md``.

The zero-trust plan §4 says:
- Enumerate what actually requires internet egress.
- If not needed, remove the NAT Gateway.

This test ensures no code path introduces a hardcoded external URL that
would require internet egress without the NAT Gateway.

See ``docs/decisions/0009-egress-analysis.md`` for the full enumeration.
"""

from __future__ import annotations

import re
from pathlib import Path

# Regex: matches HTTP(S) URLs in Python source code.
# Captures the full URL string (quoted or unquoted).
_URL_RE = re.compile(
    r"""(?:"|')https?://([^"']+)""",
)

# Internal URL patterns — these are safe, no internet egress needed.
# Also includes example/test domains used in docstrings (RFC 2606).
_INTERNAL_PATTERNS = [
    "localhost",
    "backend.test",
    "postern-local-dev.invalid",
    ".internal",
    "backend-stub",
    "evil.example",  # docstring example for URL-spoofing test (not real egress)
]


def _is_internal(url: str) -> bool:
    """Check if a URL is internal (no internet egress)."""
    return any(pattern in url for pattern in _INTERNAL_PATTERNS)


def _scan_file(filepath: Path) -> list[tuple[int, str]]:
    """Scan a Python file for HTTP(S) URLs.

    Returns list of (line_number, url) tuples for external URLs found
    in non-test, non-docstring contexts.
    """
    lines = filepath.read_text().splitlines()
    results: list[tuple[int, str]] = []

    for i, line in enumerate(lines, start=1):
        # Skip comments and docstrings (single-line)
        stripped = line.strip()
        if stripped.startswith("#"):
            continue

        for match in _URL_RE.finditer(line):
            url = match.group(0)
            if not _is_internal(url):
                results.append((i, url))

    return results


def test_no_hardcoded_external_urls_in_packages() -> None:
    """No hardcoded external URLs in packages/ source code."""
    base = Path(__file__).resolve().parents[1]
    packages_dir = base / "packages"

    external_urls: list[tuple[Path, int, str]] = []
    for pyfile in packages_dir.rglob("*.py"):
        if "test_" in str(pyfile) or "__pycache__" in str(pyfile):
            continue
        for line_no, url in _scan_file(pyfile):
            external_urls.append((pyfile, line_no, url))

    assert external_urls == [], "Hardcoded external URLs found in packages/:\n" + "\n".join(
        f"  {path}:{lineno} -> {url}" for path, lineno, url in external_urls
    )


def test_no_hardcoded_external_urls_in_services() -> None:
    """No hardcoded external URLs in services/ source code."""
    base = Path(__file__).resolve().parents[1]
    services_dir = base / "services"

    external_urls: list[tuple[Path, int, str]] = []
    for pyfile in services_dir.rglob("*.py"):
        if "test_" in str(pyfile) or "__pycache__" in str(pyfile):
            continue
        for line_no, url in _scan_file(pyfile):
            external_urls.append((pyfile, line_no, url))

    assert external_urls == [], "Hardcoded external URLs found in services/:\n" + "\n".join(
        f"  {path}:{lineno} -> {url}" for path, lineno, url in external_urls
    )


def test_no_hardcoded_external_urls_in_stub() -> None:
    """No hardcoded external URLs in stub/ source code."""
    base = Path(__file__).resolve().parents[1]
    stub_dir = base / "stub"

    external_urls: list[tuple[Path, int, str]] = []
    for pyfile in stub_dir.rglob("*.py"):
        if "test_" in str(pyfile) or "__pycache__" in str(pyfile):
            continue
        for line_no, url in _scan_file(pyfile):
            external_urls.append((pyfile, line_no, url))

    assert external_urls == [], "Hardcoded external URLs found in stub/:\n" + "\n".join(
        f"  {path}:{lineno} -> {url}" for path, lineno, url in external_urls
    )


def test_all_internal_url_patterns_are_recognized() -> None:
    """Verify the internal URL pattern list covers known URLs."""
    # These are all the internal URLs we know about — if any test fails,
    # a new internal URL was added that isn't in the pattern list.
    assert _is_internal("https://mcp-read.internal")
    assert _is_internal("http://backend.test:8081/path")
    assert _is_internal("https://postern-local-dev.invalid")
    assert _is_internal("http://backend-stub:8081/.well-known/jwks.json")
    assert _is_internal("http://localhost:8081/mint-token?sub=cust_7f3a")
    assert _is_internal("http://db.internal:5432/postern")


def test_external_url_patterns_are_detected() -> None:
    """Verify the internal URL pattern list does NOT match external URLs."""
    assert not _is_internal("https://api.stripe.com/v1/charges")
    assert not _is_internal("http://otel-collector.external:4317/v1/traces")
    assert not _is_internal("https://sns.us-east-1.amazonaws.com/")
    assert not _is_internal("http://crl.digicert.com/crl.pem")

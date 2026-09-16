"""KeySource seam: where a signing key comes from (Plan 3, Task 0).

`GeneratedKeySource` is for tests and local development; `FileKeySource` is
the shape a Vault Agent sidecar renders to disk. Nothing above this seam may
depend on which one is in use.
"""

import json
from pathlib import Path

import pytest
from joserfc.jwk import RSAKey
from postern_core.auth.keys import FileKeySource, GeneratedKeySource

_PRIVATE_PARAMS = {"d", "p", "q", "dp", "dq", "qi"}


def test_generated_source_yields_a_signing_key_with_the_given_kid() -> None:
    src = GeneratedKeySource(kid="read-1")
    assert src.signing_key().kid == "read-1"
    assert src.signing_key().is_private is True


def test_generated_source_is_stable_across_calls() -> None:
    """A minter calls signing_key() per token; a fresh key each time would
    rotate mid-flight and break every token already in the air."""
    src = GeneratedKeySource(kid="read-1")
    assert src.signing_key() is src.signing_key()


def test_public_jwks_contains_no_private_material() -> None:
    src = GeneratedKeySource(kid="read-1")
    doc = src.public_jwks()
    assert set(doc) == {"keys"}
    for entry in doc["keys"]:
        assert set(entry) & _PRIVATE_PARAMS == set(), entry
        assert entry["kid"] == "read-1"


def test_public_jwks_excludes_exactly_the_private_parameter_set() -> None:
    """A substring check ('"d"' in json.dumps(doc)) is useless: 'read-1'
    itself contains a 'd'. This instead diffs the public export against the
    same key's private export and asserts the difference is exactly the
    private parameter set, so a future joserfc export-shape change that adds
    an unlisted private field would still be caught."""
    src = GeneratedKeySource(kid="read-1")
    public_entry = src.public_jwks()["keys"][0]
    private_entry = src.signing_key().as_dict(private=True)
    assert set(private_entry) - set(public_entry) == _PRIVATE_PARAMS
    assert set(public_entry) - set(private_entry) == set()


def test_public_jwks_is_json_serialisable() -> None:
    json.dumps(GeneratedKeySource(kid="read-1").public_jwks())


def test_file_source_loads_a_pem_and_applies_the_kid(tmp_path: Path) -> None:
    """joserfc's kid is read-only with no setter, so a bare PEM import yields
    kid=None and it can never be recovered. It must be supplied at import."""
    pem = RSAKey.generate_key(2048).as_pem(private=True)
    path = tmp_path / "read.pem"
    path.write_bytes(pem)
    src = FileKeySource(path, kid="read-1")
    assert src.signing_key().kid == "read-1"
    assert set(src.public_jwks()["keys"][0]) & _PRIVATE_PARAMS == set()


def test_file_source_signing_key_is_stable_across_calls(tmp_path: Path) -> None:
    """Same stability property as the generated source: FileKeySource wraps
    a single import, not a fresh parse per call."""
    pem = RSAKey.generate_key(2048).as_pem(private=True)
    path = tmp_path / "read.pem"
    path.write_bytes(pem)
    src = FileKeySource(path, kid="read-1")
    assert src.signing_key() is src.signing_key()


def test_file_source_fails_loudly_on_a_missing_file(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        FileKeySource(tmp_path / "absent.pem", kid="read-1")


def test_file_source_rejects_a_public_key_pem(tmp_path: Path) -> None:
    """joserfc's RSAKey.import_key silently accepts a PUBLIC-key PEM and
    hands back a key with is_private=False; nothing about the call fails.
    A KeySource built from one produces a minter that cannot sign, and that
    surfaces only when the first token is minted. FileKeySource must instead
    fail at construction, not at first use."""
    pem = RSAKey.generate_key(2048).as_pem(private=False)
    path = tmp_path / "public.pem"
    path.write_bytes(pem)
    with pytest.raises(ValueError, match="private"):
        FileKeySource(path, kid="read-1")


def test_file_source_fails_loudly_on_a_malformed_pem(tmp_path: Path) -> None:
    path = tmp_path / "garbage.pem"
    path.write_bytes(b"not a pem at all")
    with pytest.raises(ValueError):
        FileKeySource(path, kid="read-1")


def test_file_source_fails_loudly_on_an_empty_file(tmp_path: Path) -> None:
    path = tmp_path / "empty.pem"
    path.write_bytes(b"")
    with pytest.raises(ValueError):
        FileKeySource(path, kid="read-1")


def test_two_sources_produce_disjoint_key_sets() -> None:
    """The whole key split rests on this."""
    read = GeneratedKeySource(kid="read-1")
    write = GeneratedKeySource(kid="write-1")
    read_kids = {e["kid"] for e in read.public_jwks()["keys"]}
    write_kids = {e["kid"] for e in write.public_jwks()["keys"]}
    assert read_kids.isdisjoint(write_kids)

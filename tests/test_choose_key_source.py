"""The one decision all three signing keys make, and its refusal.

WHY THIS FILE EXISTS. `postern_core.auth.keys.choose_key_source` replaced three
copies of an if/else on 29 September 2026, and one of its branches -- the
refusal when a Vault and a PEM are both configured -- was written with no test
at all. Measured by mutation: replacing that `if` with `if False and ...` left
`tests/test_vault_transit_key_source.py`, `tests/test_vault_live.py`,
`tests/test_key_split_is_a_property.py`, `tests/test_asgi_app.py` and
`tests/test_key_sources.py` at 101 passed. A guard nothing exercises is a
comment with a `raise` in it.

WHAT THE REFUSAL IS FOR, since it is the least obvious of the four branches.
An operator moving a key into Vault edits one variable and, if they forget the
other, gets a service that signs through Vault while a private key PEM is still
on a disk in the same container -- still readable, still the thing an RCE finds,
and now invisible because nothing signs with it any more. Ordering the branches
would make that state work. Refusing makes it a startup failure that names both
variables.
"""

from pathlib import Path

import pytest
from joserfc.jwk import RSAKey
from postern_core.auth.keys import (
    FileKeySource,
    GeneratedKeySource,
    KeySource,
    choose_key_source,
)
from postern_core.auth.vault import VaultSettings, VaultTransitKeySource

VAULT = VaultSettings(
    address="http://vault.invalid:8200",
    token="hvs.notarealtoken",  # noqa: S106 -- a literal in a test, not a credential
    token_path=None,
    mount="transit",
    timeout_seconds=1.0,
    public_key_ttl_seconds=300.0,
)


@pytest.fixture
def pem(tmp_path: Path) -> Path:
    path = tmp_path / "read.pem"
    path.write_bytes(RSAKey.generate_key(2048).as_pem(private=True))
    return path


def _choose(**overrides: object) -> KeySource:
    arguments: dict[str, object] = {
        "role": "READ",
        "kid": "read-1",
        "vault": None,
        "vault_key_name": "postern-read",
        "pem_path": None,
        "pem_env_var": "POSTERN_READ_KEY_PEM_PATH",
    }
    arguments.update(overrides)
    return choose_key_source(**arguments)  # type: ignore[arg-type]


class TestTheFourBranches:
    def test_a_vault_gives_a_transit_source(self) -> None:
        """No network here: the constructor fetches nothing, so this asserts
        the BRANCH and not the Vault. `tests/test_vault_live.py` is where a
        real one answers."""
        source = _choose(vault=VAULT)
        assert isinstance(source, VaultTransitKeySource)
        source.close()

    def test_a_pem_gives_a_file_source(self, pem: Path) -> None:
        assert isinstance(_choose(pem_path=str(pem)), FileKeySource)

    def test_neither_gives_a_generated_source(self) -> None:
        with pytest.warns(RuntimeWarning, match="generated in process"):
            assert isinstance(_choose(), GeneratedKeySource)

    def test_the_ephemeral_warning_names_the_variable_that_would_fix_it(self) -> None:
        with pytest.warns(RuntimeWarning, match="POSTERN_WRITE_KEY_PEM_PATH"):
            _choose(role="WRITE", pem_env_var="POSTERN_WRITE_KEY_PEM_PATH")


class TestBothIsRefused:
    """The mutation that survived until this class existed."""

    def test_a_vault_and_a_pem_together_raise(self, pem: Path) -> None:
        with pytest.raises(ValueError):
            _choose(vault=VAULT, pem_path=str(pem))

    def test_the_refusal_names_both_variables_so_the_operator_can_pick_one(self, pem: Path) -> None:
        with pytest.raises(ValueError) as caught:
            _choose(vault=VAULT, pem_path=str(pem))
        message = str(caught.value)
        assert "POSTERN_VAULT_ADDR" in message
        assert "POSTERN_READ_KEY_PEM_PATH" in message
        assert "READ" in message

    def test_the_write_half_is_refused_the_same_way_and_names_its_own_variable(
        self, pem: Path
    ) -> None:
        with pytest.raises(ValueError, match="POSTERN_WRITE_KEY_PEM_PATH") as caught:
            _choose(
                role="WRITE",
                kid="write-1",
                vault=VAULT,
                vault_key_name="postern-write",
                pem_path=str(pem),
                pem_env_var="POSTERN_WRITE_KEY_PEM_PATH",
            )
        assert "WRITE" in str(caught.value)

    def test_nothing_is_constructed_before_the_refusal(self, pem: Path) -> None:
        """No RSA key generated, no PEM read, no `httpx2.Client` opened. The
        guard is the first statement in the function and this is what keeps it
        there: a refusal that happens after a resource is built leaks the
        resource, which is the reason `services/api/main.py` runs the startup
        probe before the backend client and the database exist."""
        import warnings

        with warnings.catch_warnings(record=True) as recorded:
            warnings.simplefilter("always")
            with pytest.raises(ValueError):
                _choose(vault=VAULT, pem_path=str(pem))
        assert [w for w in recorded if issubclass(w.category, RuntimeWarning)] == []


class TestTheSignatureIsTheControl:
    """One key in, one source out, checked as a signature rather than argued.

    `services/api/jwks.py`'s docstring measured what a shared helper costs on
    the JWKS side: a "take several key sources" convenience there voids the
    read/write split outright. This function is the same kind of shared helper
    one layer down, so the same convenience must be unwritable here.
    """

    def test_no_parameter_names_two_keys_and_no_return_carries_two_sources(self) -> None:
        import inspect

        signature = inspect.signature(choose_key_source)
        assert set(signature.parameters) == {
            "role",
            "kid",
            "vault",
            "vault_key_name",
            "pem_path",
            "pem_env_var",
        }
        assert signature.return_annotation is KeySource

    def test_every_parameter_is_keyword_only(self) -> None:
        """Positionally, `role` and `kid` are both strings and so are
        `vault_key_name` and `pem_env_var`: a transposed call would type-check
        and would publish a key under the wrong name."""
        import inspect

        kinds = {p.kind for p in inspect.signature(choose_key_source).parameters.values()}
        assert kinds == {inspect.Parameter.KEYWORD_ONLY}

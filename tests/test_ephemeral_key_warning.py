"""An in-process signing key must not be built silently, in either service.

Before this file, `services/api/main.py::_read_key_source` and
`services/confirm/minter.py::_write_key_source` both returned a
`GeneratedKeySource` on an unset PEM path with no exception, no log line and
no warning, while the docstring one line above each said a deployment must
set the path. `docs/verification/2026-09-18-multi-replica-jwks.md` measured
what the silence costs: two live `api` replicas published two different
2048-bit moduli under the one `kid` `read-1`, and a real token minted by one
failed against the other's JWKS as
`joserfc.errors.BadSignatureError('bad_signature: ')` -- an empty
description, indistinguishable from a forged token, where a genuine `kid`
mismatch would have raised `InvalidKeyIdError("invalid_key_id: No key for
kid: 'read-1'")` and named the problem.

Four properties are pinned here, and the first is the one that matters
most:

1. The warning is UNCONDITIONAL. It fires under the exact settings shape
   `_refuse_stub_minter_in_production` used to call "production"
   (`customer_jwks_uri` and `customer_token_issuer` both set) and equally
   under `Settings.for_testing()`, because it never asks which of the two
   it is looking at. `d203606` deleted that guard precisely because it
   inferred a deployment from a settings shape and got it backwards.
2. It fires for BOTH services. The write key is the half with more at
   stake and the easier one to leave out.
3. It does NOT fire when a PEM path is set. The PEM here is a real 2048-bit
   RSA private key written to `tmp_path`, not a mock, so `FileKeySource`
   does its actual import and public-key rejection.
4. The message names the consequence -- restart, replica, the fixed `kid`,
   `BadSignatureError` versus `InvalidKeyIdError`, the record that measured
   it -- and not merely the state. "Generated an ephemeral key" gives an
   operator nothing to act on.

Nothing here asserts a refusal, and that is deliberate: a refusal would stop
`docker compose up` and `Settings.for_testing()`, and the only way back
would be an override flag, which is what `POSTERN_ALLOW_STUB_TOKEN_MINTER`
was.
"""

import warnings
from collections.abc import Callable
from pathlib import Path

import pytest
from joserfc.jwk import RSAKey
from postern_core.auth.device_keys import no_enrolled_devices

from services.api.main import create_app
from services.api.settings import Settings
from services.confirm.main import create_confirm_app
from services.confirm.settings import ConfirmSettings

# The substring every ephemeral-key warning carries, whichever service emits
# it. Matching on this rather than on the whole paragraph keeps these tests
# from breaking on a wording change while still failing if the warning stops
# being emitted at all.
MARKER = "signing key generated in process"
RECORD = "docs/verification/2026-09-18-multi-replica-jwks.md"
REPO_ROOT = Path(__file__).resolve().parent.parent


def _private_pem(tmp_path: Path, name: str, kid: str) -> str:
    """A real 2048-bit RSA private key on disk, not a mock.

    `FileKeySource` reads the bytes, imports them through joserfc and
    rejects a public key, so handing it a patched object would prove the
    branch was taken without proving the branch works.
    """
    key = RSAKey.generate_key(2048, parameters={"kid": kid, "use": "sig", "alg": "RS256"})
    path = tmp_path / name
    path.write_bytes(key.as_pem(private=True))
    return str(path)


def _ephemeral_warnings(build: Callable[[], object]) -> list[str]:
    """Every ephemeral-key warning `build()` emits, as text.

    `catch_warnings` plus `simplefilter("always")` rather than `pytest.warns`
    because these call sites need to assert ZERO of them, and because the
    default `"default"` action deduplicates by (text, module, lineno), which
    would hide a second warning from a second `create_app()` in one process.
    """
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        build()
    return [str(w.message) for w in caught if issubclass(w.category, RuntimeWarning)]


# --- 1. Unconditional: no settings shape turns it off ----------------------


def test_the_api_warning_fires_under_a_production_shaped_configuration() -> None:
    """The whole design, in one test.

    `_refuse_stub_minter_in_production` decided "this is production" from
    exactly these two fields being set and never from what `create_app`
    built, so once `ReadTokenMinter` replaced `StubTokenMinter` it refused
    the genuine deployments and nothing else (`d203606`, whose removal note
    `services/api/main.py` still carries in its module docstring). This
    warning forms no opinion about the deployment at all: same input, no
    refusal, and the warning still fires
    because the key really was generated.
    """
    settings = Settings(
        backend_base_url="https://backend.test",
        customer_jwks_uri="https://issuer.test/.well-known/jwks.json",
        customer_token_issuer="https://issuer.test",  # noqa: S106
    )
    messages = _ephemeral_warnings(lambda: create_app(settings))
    assert [m for m in messages if MARKER in m], messages


# --- 2. It fires for both services ----------------------------------------


def test_the_api_composition_root_warns_when_no_read_pem_path_is_set() -> None:
    with pytest.warns(RuntimeWarning, match="READ signing key generated in process"):
        create_app(Settings.for_testing())


def test_the_confirm_composition_root_warns_when_no_write_pem_path_is_set() -> None:
    """The write key is the more dangerous half: it is what will sign
    `payments.svc` and `cards.svc` tokens (`services/confirm/minter.py`'s
    `WRITE_SCOPES`), and `ConfirmSettings` has no field at all besides the
    three key fields, so nothing else in that service could ever hint at a
    misconfiguration."""
    with pytest.warns(RuntimeWarning, match="WRITE signing key generated in process"):
        create_confirm_app(ConfirmSettings.for_testing(), device_key_store=no_enrolled_devices())


# --- 3. A configured PEM is silent ----------------------------------------


def test_the_api_composition_root_is_silent_when_a_real_pem_is_configured(tmp_path: Path) -> None:
    settings = Settings(
        backend_base_url="https://backend.test",
        read_key_pem_path=_private_pem(tmp_path, "read.pem", "read-1"),
    )
    assert [m for m in _ephemeral_warnings(lambda: create_app(settings)) if MARKER in m] == []


def test_the_confirm_composition_root_is_silent_when_a_real_pem_is_configured(
    tmp_path: Path,
) -> None:
    settings = ConfirmSettings(
        write_key_pem_path=_private_pem(tmp_path, "write.pem", "write-1"),
        read_key_pem_path=_private_pem(tmp_path, "read.pem", "read-1"),
        session_key_pem_path=_private_pem(tmp_path, "session.pem", "session-1"),
        # Required since the confirm service gained inbound authentication:
        # `create_confirm_app` refuses to build without all three (there is no
        # unauthenticated mode on the write path). This test is about signing
        # keys, so the values only have to be present and unreachable.
        app_assertion_jwks_uri="https://app.postern.invalid/.well-known/jwks.json",
        app_assertion_issuer="https://app.postern.invalid",
        app_assertion_audience="postern-confirm",
        # The two development flags `ConfirmSettings.for_testing` sets: this
        # settings object is built by hand, so it gets the safe defaults.
        allow_non_uri_audience=True,
        allow_process_local_sessions=True,
    )
    assert [
        m
        for m in _ephemeral_warnings(
            lambda: create_confirm_app(settings, device_key_store=no_enrolled_devices())
        )
        if MARKER in m
    ] == []


# --- 4. The message names the consequence, not only the state -------------


@pytest.mark.parametrize(
    ("build", "expected_count"),
    [
        pytest.param(
            lambda: create_app(Settings.for_testing()),
            1,
            id="api",
        ),
        pytest.param(
            lambda: create_confirm_app(
                ConfirmSettings.for_testing(), device_key_store=no_enrolled_devices()
            ),
            3,  # write + read (device grant exception) + session
            id="confirm",
        ),
    ],
)
def test_the_warning_names_the_consequence_not_only_the_state(
    build: Callable[[], object], expected_count: int
) -> None:
    """Six fragments, each one a thing an operator can act on or look up.

    A message that said only "generated an ephemeral key" would pass no part
    of this: the state is already in the docstrings of both
    `_read_key_source` and `_write_key_source` and has been since Plan 3
    Task 2, and stating it again at runtime adds nothing.
    """
    messages = [m for m in _ephemeral_warnings(build) if MARKER in m]
    assert len(messages) == expected_count, messages
    # Each message must contain the consequence fragments.
    for message in messages:
        for fragment in (
            "signing key generated in process",
            "discard it on exit",
            "Every restart and every replica signs with a different key",
            "BadSignatureError('bad_signature: ')",
            "InvalidKeyIdError",
            RECORD,
        ):
            assert fragment in message, (fragment, message)
    # The API service has exactly one warning about the read key.
    if expected_count == 1:
        assert "POSTERN_READ_KEY_PEM_PATH" in messages[0]
    # The confirm service has warnings for the write, read and session keys.
    if expected_count == 3:
        write_msg = [m for m in messages if "POSTERN_WRITE_KEY_PEM_PATH" in m]
        read_msg = [m for m in messages if "POSTERN_READ_KEY_PEM_PATH" in m]
        session_msg = [m for m in messages if "POSTERN_SESSION_KEY_PEM_PATH" in m]
        assert len(write_msg) == 1
        assert len(read_msg) == 1
        assert len(session_msg) == 1


def test_the_record_the_warning_cites_exists() -> None:
    """A citation an operator cannot follow is worse than no citation: it
    costs them the lookup and then tells them nothing. This fails if the
    record is renamed or moved without the warning text following it."""
    assert (REPO_ROOT / RECORD).is_file(), REPO_ROOT / RECORD

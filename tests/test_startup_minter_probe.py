"""A composition root must not start holding a minter whose tokens it cannot verify.

`d203606` deleted `_refuse_stub_minter_in_production` because that guard asked
`Settings` which deployment this was (`customer_jwks_uri` and
`customer_token_issuer` both set) and never asked `create_app` what it had
built, so once `ReadTokenMinter` replaced `StubTokenMinter` the guard refused
exactly the deployments running the genuine minter. `services/api/main.py`'s
module docstring records that and states what was left behind: nothing checked
minter identity at startup at all.

`postern_core.auth.minter_probe.refuse_unverifiable_minter` is the
replacement, and the axis these tests are built around is the one the old
guard got wrong. Every case below fixes the minter and varies the settings, or
fixes the settings and varies the minter; the answer follows the minter every
time and follows the settings never. A guard with the old defect passes none of
them.

What the probe asks is not "is this production?" but "does the credential this
process just minted verify against the key set this same process publishes?".
That question has one right answer in every environment this repo supports,
which is why the control can refuse rather than warn and still needs no
override flag. `refuse_unverifiable_minter`'s docstring carries the rest of
that argument, including why the ephemeral-key control next door
(`postern_core.auth.keys.warn_ephemeral_signing_key`, pinned by
`tests/test_ephemeral_key_warning.py`) warns where this one refuses.
"""

import pytest
from joserfc.errors import BadSignatureError
from postern_core.auth.internal_jwt import InternalTokenMinter
from postern_core.auth.keys import GeneratedKeySource, KeySource
from postern_core.auth.minter_probe import refuse_unverifiable_minter
from postern_core.auth.read_minter import ReadTokenMinter
from postern_core.auth.revocation import unchecked_revocation
from postern_core.facade.client import StubTokenMinter
from postern_core.identity import CustomerRef

from services.api import main as api_main
from services.api.main import create_app
from services.api.settings import Settings

PROBE = CustomerRef(value="cust_probe")
READ_ISSUER = "https://mcp-read.internal"

# The two settings shapes the deleted guard could not tell apart from what
# `create_app` had built. `for_testing()` is what every test and the local
# docker-compose stack use; the second is the shape `_refuse_stub_minter_in_
# production` called "production" and refused on.
SETTINGS_SHAPES = [
    pytest.param(Settings.for_testing(), id="for_testing"),
    pytest.param(
        Settings(
            backend_base_url="https://backend.test",
            customer_jwks_uri="https://issuer.test/.well-known/jwks.json",
            customer_token_issuer="https://issuer.test",  # noqa: S106
        ),
        id="production_shaped",
    ),
]


def _read_minter(key_source: KeySource) -> ReadTokenMinter:
    # `unchecked_revocation` because this file measures the startup probe, not
    # ZT-7: the minter's default provider refuses when no revocation decision
    # has been published for the call, and there is no request here to publish
    # one. See `postern_core.auth.revocation`'s `require_revocation_decision`.
    return ReadTokenMinter(
        InternalTokenMinter(issuer=READ_ISSUER, key_source=key_source),
        revocation_decision=unchecked_revocation,
    )


# --- The answer follows the minter, in both settings shapes ----------------


@pytest.mark.parametrize("settings", SETTINGS_SHAPES)
def test_the_genuine_minter_starts_under_either_settings_shape(settings: Settings) -> None:
    """The half the old guard got backwards.

    `create_app` builds a `ReadTokenMinter` over the key source its own JWKS
    route publishes, so the probe verifies and the app assembles. Under the
    right-hand shape the deleted guard raised `RuntimeError` naming
    `StubTokenMinter` at a process that was running the real one.
    """
    assert create_app(settings).state.postern_read_key_source is not None


@pytest.mark.parametrize("settings", SETTINGS_SHAPES)
def test_a_stub_minter_wired_into_the_composition_root_is_refused(
    settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The hazard, reproduced the only way it can actually occur.

    No `Settings` field, no environment variable and no `create_app` parameter
    selects a minter: every `StubTokenMinter()` in this repository is
    constructed inside `tests/`, none of them by a composition root. The one
    route into the API composition root is an edit to `services/api/main.py`,
    so this patches the name that file binds, which is what such an edit would
    change.

    Both shapes refuse, because the probe never looks at either one.
    """
    monkeypatch.setattr(api_main, "ReadTokenMinter", lambda _inner, **_kw: StubTokenMinter())
    with pytest.raises(RuntimeError, match="StubTokenMinter"):
        create_app(settings)


def test_the_refusal_names_the_object_the_process_built(monkeypatch: pytest.MonkeyPatch) -> None:
    """`StubTokenMinter` is the actionable half of the message: it names the
    edit to undo. The role and the absence of an override flag are the rest.
    """
    monkeypatch.setattr(api_main, "ReadTokenMinter", lambda _inner, **_kw: StubTokenMinter())
    with pytest.raises(RuntimeError) as refusal:
        create_app(Settings.for_testing())
    message = str(refusal.value)
    for fragment in ("READ", "StubTokenMinter", "no override flag"):
        assert fragment in message, (fragment, message)


# --- What the probe actually checks ---------------------------------------


def test_a_minter_signing_with_a_key_this_process_does_not_publish_is_refused() -> None:
    """The check is cryptographic, not a shape test.

    Both key sources carry the kid `read-1`, so the published key set resolves
    the token's kid and then fails on the signature: measured
    `BadSignatureError('bad_signature: ')`, the same failure
    `docs/verification/2026-09-18-multi-replica-jwks.md` measured between two
    replicas. A probe that only asked whether the credential looked like a JWT
    would accept this token.
    """
    published = GeneratedKeySource(kid="read-1")
    minter = _read_minter(GeneratedKeySource(kid="read-1"))
    with pytest.raises(RuntimeError, match="ReadTokenMinter") as refusal:
        refuse_unverifiable_minter(
            lambda: minter(PROBE, "accounts.svc"),
            built=minter,
            key_source=published,
            role="READ",
        )
    assert isinstance(refusal.value.__cause__, BadSignatureError)


def test_a_segment_count_would_not_discriminate_but_this_check_does() -> None:
    """Why the probe decodes rather than counts.

    `stub.read.cust_probe` is itself three dot-separated segments --
    `stub/backend.py::_subject` documents that collision and orders its own
    checks around it -- so `len(token.split(".")) == 3` accepts the stub.
    Decoding rejects it: `stub` is not a base64url JOSE header.
    """
    stub = StubTokenMinter()
    with pytest.warns(RuntimeWarning, match="StubTokenMinter"):
        token = stub(PROBE, "accounts.svc")
    assert len(token.split(".")) == 3

    with pytest.raises(RuntimeError, match="StubTokenMinter"):
        refuse_unverifiable_minter(
            lambda: token,
            built=stub,
            key_source=GeneratedKeySource(kid="read-1"),
            role="READ",
        )


def test_the_control_a_minter_over_the_published_key_is_accepted() -> None:
    """Without this the tests above prove nothing: a function that raised
    unconditionally would satisfy every one of them."""
    source = GeneratedKeySource(kid="read-1")
    minter = _read_minter(source)
    refuse_unverifiable_minter(
        lambda: minter(PROBE, "accounts.svc"), built=minter, key_source=source, role="READ"
    )


def test_the_refusal_does_not_carry_the_credential_it_minted() -> None:
    """A refusal that pasted the token into the message would put a live
    signed credential in a startup log. The token here is genuine -- a real
    RS256 token for a synthetic subject -- and only the key set it is checked
    against is wrong, so there is a credential available to leak.
    """
    minter = _read_minter(GeneratedKeySource(kid="read-1"))
    token = minter(PROBE, "accounts.svc")
    with pytest.raises(RuntimeError) as refusal:
        refuse_unverifiable_minter(
            lambda: token,
            built=minter,
            key_source=GeneratedKeySource(kid="read-1"),
            role="READ",
        )
    message = str(refusal.value)
    assert token not in message
    for segment in token.split("."):
        assert segment not in message, segment


def test_a_minter_that_cannot_mint_at_all_fails_with_its_own_exception() -> None:
    """Not caught, and that is the decision: `ReadTokenMinter` raises
    `KeyError` for an audience outside `READ_SCOPES`, and a `KeyError` naming
    the audience says more about the miswiring than any message this function
    could build around it. Startup still stops, which is the outcome the
    control exists for.
    """
    minter = _read_minter(GeneratedKeySource(kid="read-1"))

    def mint() -> str:
        return minter(PROBE, "payments.svc")

    with pytest.raises(KeyError, match="payments.svc"):
        refuse_unverifiable_minter(
            mint, built=minter, key_source=GeneratedKeySource(kid="read-1"), role="READ"
        )

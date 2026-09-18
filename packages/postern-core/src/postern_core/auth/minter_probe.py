"""Does a credential this process mints verify against the key it publishes?

One question, asked once, at the composition root, about the objects that
root has just built. It is the narrowest thing that can tell a genuine minter
from a placeholder without asking `Settings` anything, which is the property
`d203606` removed and did not replace.
"""

from collections.abc import Callable

from joserfc import jwt
from joserfc.errors import JoseError
from joserfc.jwk import KeySet

from postern_core.auth.keys import KeySource


def refuse_unverifiable_minter(
    mint: Callable[[], str], *, built: object, key_source: KeySource, role: str
) -> None:
    """Mint one token and refuse to start unless this process can verify it.

    WHAT IT ASKS, AND WHAT IT REFUSES TO ASK. The deleted
    `_refuse_stub_minter_in_production` inferred a deployment from a settings
    shape -- `customer_jwks_uri` and `customer_token_issuer` both set -- and
    once the real `ReadTokenMinter` replaced `StubTokenMinter` it refused
    exactly the deployments running the genuine minter and nothing else
    (`services/api/main.py`'s module docstring records the measurement). This
    function reads no settings at all. It calls the minter the caller just
    built, hands the result to the key set that same caller publishes, and
    refuses if the two do not agree. `warn_ephemeral_signing_key` next door
    reaches the same conclusion from the other direction: a control that never
    forms an opinion about production cannot be wrong about one.

    A REFUSAL, where the ephemeral-key control warns. That control's argument
    for warning does not transfer, and the difference is checkable rather than
    a matter of taste:

    1. Its hazard is REACHABLE BY CONFIGURATION and is the documented local
       path: an unset PEM path is the default in `Settings.for_testing()`, in
       nearly every test and in the docker-compose stack, so refusing there
       refuses supported deployments, and the way back would be a named
       override flag -- which is what `POSTERN_ALLOW_STUB_TOKEN_MINTER` was.
       ("Nearly": `tests/test_ephemeral_key_warning.py` and
       `tests/test_asgi_app.py` each configure a real `read_key_pem_path`, and
       `tests/test_key_sources.py` builds `FileKeySource` directly. An earlier
       draft of this line said EVERY test, which is false and sent a reviewer
       looking for a coverage hole that does not exist -- see "BOTH KEY
       BRANCHES" below.) This hazard is
       reachable by no configuration: no `Settings` field, no environment
       variable and no `create_app` parameter selects a minter, and every
       `StubTokenMinter()` in this repository is constructed under `tests/`,
       none of them by a composition root. A refusal here has nothing
       legitimate to refuse, so it needs no flag, and there is none.
    2. The two failures point in opposite directions. An ephemeral key signs
       GENUINE tokens; a verifier without the matching public key rejects them
       (`docs/verification/2026-09-18-multi-replica-jwks.md` measured
       `BadSignatureError`), so that hazard fails closed and loudly. A
       placeholder's token is not signed at all: `StubTokenMinter` returns the
       literal `stub.read.<customer>`, whose customer half is self-asserted,
       and `stub/backend.py::_subject` -- the backend this repo ships for
       local development -- reads that prefix and scopes its answers by
       whatever follows it. Against any backend that does not verify
       signatures the fake token is not rejected, it is believed, and the
       identity layer becomes string concatenation. A hazard that fails OPEN
       cannot be delegated to a warning a running process prints past.

    WHAT IT CHECKS, exactly: that `mint()` returns a compact JWS which
    `key_source.public_jwks()` verifies. Not the issuer, not the audience, not
    the scope, not the expiry: measured, `jwt.decode` accepts a correctly
    signed token carrying `exp: 1`, a foreign `iss` and an `aud` naming no
    service, because claim policy lives in `JWTClaimsRegistry` and belongs to
    the gateway that receives the token rather than to the process that signs
    it. It does catch one thing beyond a placeholder: a
    minter built over a key source other than the one the caller publishes,
    which is the same miswiring `tests/test_key_split_is_a_property.py`
    simulates deliberately.

    ONE THING IT CANNOT SEE: a token carrying no `kid` header at all.
    Measured against a `GeneratedKeySource`'s own published set, a kid-less
    RS256 token is ACCEPTED when the set holds one key, and raises
    `InvalidKeyIdError("invalid_key_id: No key for kid: 'None'")` once the set
    holds two. Every process here publishes exactly one key, so if
    `InternalTokenMinter` ever stopped putting `kid` in the JOSE header this
    probe would keep passing while a real verifier resolving against a
    multi-key set failed. The kid is set today from `key.kid` in
    `InternalTokenMinter.mint`, and
    `tests/test_internal_jwt.py::test_the_header_names_the_signing_kid` is
    where that contract is pinned; this function is not a second guard on it.

    BOTH KEY BRANCHES REACH THIS CHECK IN CI, which is worth stating here
    because the file is small and the evidence for it is not local to it. The
    body below has no branch on where the key came from, and both
    `GeneratedKeySource` and `FileKeySource` derive `signing_key()` and
    `public_jwks()` from a single `self._key`, with `create_app` handing that
    one object to both the minter and the JWKS route, so choosing a branch
    cannot produce the mismatch this probe looks for: producing it takes an
    edit to `create_app`, which `tests/test_startup_minter_probe.py` models by
    patching the minter. The PEM branch is nonetheless exercised through here
    on every run. Measured, by replacing this function's body with an
    unconditional refusal:
    `tests/test_asgi_app.py::test_a_configured_pem_path_signs_instead_of_a_generated_key`
    (which configures a non-default kid, `read-file`, so a kid divergence in
    `create_app` would surface through it) and
    `tests/test_ephemeral_key_warning.py::test_the_api_composition_root_is_silent_when_a_real_pem_is_configured`
    both turn red. A PEM-branch test of this function's own would add no
    coverage.

    WHAT IT COSTS AT STARTUP, today and later. Today: measured on one
    developer machine, a mean of 0.96ms over 20 runs, against 70.7ms for the
    `GeneratedKeySource` construction already on that path in the same
    measurement -- one RSA signature and one verification, no I/O, nothing
    that can block. Later is the part worth writing down: `KeySource` is the
    seam Vault lands behind, and if a Vault-backed implementation ever makes
    minting a REMOTE signing call, this line converts "Vault unreachable, the
    first tool call fails" into "Vault unreachable, the container never
    becomes ready" -- a crash loop instead of a degraded pod. That is a
    defensible trade for a process whose whole job is minting those tokens,
    but it is a trade, and whoever lands remote signing should decide it on
    purpose rather than discover it in a rollout.

    Measured against joserfc 1.7.5, all four rejections are `JoseError`
    subclasses, which is why that one `except` is enough: the stub's literal
    output raises `DecodeError('decode_error: Invalid header')` (`stub` is not
    a base64url JOSE header), an empty or non-JWS string raises
    `DecodeError('decode_error: Invalid JSON Web Signature')`, a token signed
    by another key under a published kid raises
    `BadSignatureError('bad_signature: ')`, and an unpublished kid raises
    `InvalidKeyIdError`.

    `mint` is PRE-BOUND by the caller, taking nothing and returning the token,
    for the reason `postern_core.facade.client.BackendRequestHook` is
    pre-bound one layer down: the composition root
    knows which customer reference and which audience its minter needs
    (`ReadTokenMinter` wants a `CustomerRef` and a read audience,
    `services/confirm/minter.py::WriteTokenMinter.mint` wants a subject
    string, an audience and a scope), and this function needs to know none of
    it. `built` is the object `mint` calls, passed separately because a
    pre-bound callable cannot name it; it is read for the refusal message and
    for nothing else.

    A `mint` that RAISES is not caught. `ReadTokenMinter` raises `KeyError`
    for an audience outside `READ_SCOPES`, and that exception names the
    miswiring better than any message built around it would. Startup stops
    either way, which is the outcome this control exists for.

    IT DOES NOT DUPLICATE `StubTokenMinter`'s own `RuntimeWarning`. That one
    fires on every mint, in a running process, and reports the same hazard
    once per customer request to whatever is capturing warnings; it cannot
    stop anything, because a placeholder cannot decide a deployment question
    from inside itself. This fires once, before the app is assembled, and
    ends the process. The probe mint below does trigger that warning one more
    time on its way to refusing, which costs a line of startup output on a
    process that is about to fail anyway.

    WHERE IT IS CALLED: `services/api/main.py::create_app` only, and not
    because the write path matters less -- it is the half with more at stake.
    `services/confirm/main.py::create_confirm_app` builds a `WriteTokenMinter`
    and then discards it, keeping only the `KeySource` for its JWKS route, and
    `services/confirm/minter.py`'s module docstring records that nothing in
    that service derives a scope from `WRITE_SCOPES` yet. There is no held
    minter there to report on, and probing the discarded one would make that
    process mint its first `payments:execute` token ever purely as a
    self-test, in a release where nothing else mints one at all. When Plan
    5's approval callback gives that process a minter it keeps and uses, this
    call belongs there too.
    """
    token = mint()
    try:
        jwt.decode(token, KeySet.import_key_set(key_source.public_jwks()), algorithms=["RS256"])
    except JoseError as exc:
        # `type(exc).__name__` and never `str(exc)`: joserfc's descriptions
        # are short and key-shaped rather than token-shaped, but this message
        # is the one that lands in a startup log, and nothing formatted here
        # can carry the credential that was just minted. The chained
        # exception keeps the full description for whoever reads the
        # traceback.
        raise RuntimeError(
            f"{role} token minter refused at startup: this process built a "
            f"{type(built).__name__}, whose token does not verify against the key set "
            f"this same process publishes ({type(exc).__name__}). A credential this "
            f"process cannot verify is not one a backend will reject -- a backend that "
            f"does not check signatures believes it, and its subject is then whatever "
            f"the token says. There is no override flag: build the minter over the key "
            f"source this process publishes."
        ) from exc

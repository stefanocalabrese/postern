"""Inbound authentication on the write path (audit findings C-01, C-02).

What this file pins is the MECHANISM: that the confirm service refuses to
start without inbound authentication, that every route it serves is denied by
default, and that no way of presenting a bad token gets further than any
other. The individual flows are pinned where they live --
``tests/test_device_grant.py`` for the device grant, ``tests/test_callback.py``
and ``tests/test_approval_integration.py`` for challenge approval.

The audit's finding was not that one check was weak. It was that
``services/confirm/main.py`` read ``app = Starlette(routes=routes)``, with no
``middleware=`` argument at all, and that a grep for ``Authorization`` across
``services/confirm/*.py`` returned a single OUTBOUND header. So the tests here
are mostly about absence being impossible rather than about any one check
being correct.
"""

from __future__ import annotations

import dataclasses
import logging
import re
import time
from typing import Any

import httpx2
import pytest
from fastmcp.server.auth.providers.jwt import JWTVerifier, RSAKeyPair
from joserfc import jwt as jose_jwt
from joserfc.jwk import RSAKey
from postern_core.auth.device_keys import no_enrolled_devices
from starlette.applications import Starlette

from services.confirm.auth import (
    ASSERTION_CLOCK_SKEW_SECONDS,
    ASSERTION_STATE_KEY,
    PUBLIC_PATHS,
    AppAssertion,
    AppAssertionMiddleware,
)
from services.confirm.main import create_confirm_app
from services.confirm.settings import ConfirmSettings

ISSUER = "https://app.test.invalid"
AUDIENCE = "postern-confirm"
CUSTOMER = "cust_7f3a"


# ---------------------------------------------------------------------------
# Fixtures.
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def key_pair() -> RSAKeyPair:
    """Module-scoped: generating 2048 bits of RSA per test is the slowest
    thing this file would otherwise do, and nothing here mutates the pair."""
    return RSAKeyPair.generate()


@pytest.fixture(autouse=True)
def _a_reachable_database(pg_url: str) -> None:
    """Every app in this file needs Postgres, as of 2026-09-26.

    ``POST /approve`` writes one ``audit_log`` row per pairing attempt and
    fails closed if it cannot, so an app pointed at the field default of
    ``localhost:5432`` answers 500 to every request this file makes.
    ``tests/conftest.py``'s session-scoped ``pg_url`` starts the container and
    exports ``POSTERN_DATABASE_URL``; ``ConfirmSettings.for_testing`` reads
    that variable, so depending on the fixture is all this file has to do.

    Autouse rather than a parameter on each app builder: several of the
    ``create_confirm_app`` calls here are inside test methods, and threading a
    URL down to each would touch more lines than the behaviour being tested.
    """


@pytest.fixture
def app(key_pair: RSAKeyPair) -> Starlette:
    verifier = JWTVerifier(public_key=key_pair.public_key, issuer=ISSUER, audience=AUDIENCE)
    return create_confirm_app(
        ConfirmSettings.for_testing(),
        assertion_verifier=verifier,
        device_key_store=no_enrolled_devices(),
    )


def client(app: Starlette) -> httpx2.AsyncClient:
    return httpx2.AsyncClient(
        transport=httpx2.ASGITransport(app=app), base_url="http://confirm.test"
    )


def bearer(key_pair: RSAKeyPair, subject: str = CUSTOMER, **kwargs: Any) -> dict[str, str]:
    """A valid assertion unless ``kwargs`` says otherwise.

    ``expires_in_seconds`` defaults to 60 because ``RSAKeyPair.create_token``
    defaults it to 3600, which is past the confirm service's ceiling on how
    far ahead an assertion's ``exp`` may sit, and would be refused.
    """
    kwargs.setdefault("issuer", ISSUER)
    kwargs.setdefault("audience", AUDIENCE)
    kwargs.setdefault("expires_in_seconds", 60)
    return {"Authorization": f"Bearer {key_pair.create_token(subject=subject, **kwargs)}"}


def raw_bearer(key_pair: RSAKeyPair, claims: dict[str, Any]) -> dict[str, str]:
    """Sign exactly ``claims``, with nothing added.

    ``RSAKeyPair.create_token`` always writes ``iat`` and ``exp``, so it cannot
    mint the assertion this service has to refuse: one with no ``exp`` at all.
    """
    key = RSAKey.import_key(key_pair.private_key.get_secret_value())
    token = jose_jwt.encode({"alg": "RS256"}, claims, key, algorithms=["RS256"])
    return {"Authorization": f"Bearer {token}"}


def claims_now(**overrides: Any) -> dict[str, Any]:
    """The claims of a valid assertion minted this second, with ``overrides``.

    An override of ``None`` deletes the claim rather than setting it null.
    """
    now = int(time.time())
    claims: dict[str, Any] = {
        "sub": CUSTOMER,
        "iss": ISSUER,
        "aud": AUDIENCE,
        "iat": now,
        "exp": now + 60,
    }
    for name, value in overrides.items():
        if value is None:
            claims.pop(name, None)
        else:
            claims[name] = value
    return claims


# ---------------------------------------------------------------------------
# 1. The service refuses to start without inbound authentication.
# ---------------------------------------------------------------------------

_COMPLETE = {
    "app_assertion_jwks_uri": "https://app.test.invalid/.well-known/jwks.json",
    "app_assertion_issuer": ISSUER,
    "app_assertion_audience": AUDIENCE,
}


def _settings(omitted: str | None = None) -> ConfirmSettings:
    """``_COMPLETE``, with one field knocked out. Spelled out rather than
    ``ConfirmSettings(**values)`` so mypy checks each argument against the
    real field types instead of collapsing them to ``str``."""
    v = {k: (None if k == omitted else value) for k, value in _COMPLETE.items()}
    return ConfirmSettings(
        app_assertion_jwks_uri=v["app_assertion_jwks_uri"],
        app_assertion_issuer=v["app_assertion_issuer"],
        app_assertion_audience=v["app_assertion_audience"],
    )


@pytest.mark.parametrize("omitted", sorted(_COMPLETE))
def test_an_incomplete_assertion_config_refuses_to_build(omitted: str) -> None:
    """Any one of the three missing is a startup failure, not a warning.

    ``services/api/server.py`` stops one step short of this on purpose: it
    raises only when EXACTLY ONE of its pair is set, because neither set is
    its documented no-auth path for local development. This service has no
    such path. It holds the write signing key and its endpoints approve money
    movement, so the unauthenticated configuration is not one to support for
    convenience -- it is the audit finding, and it should be unrepresentable.
    """
    settings = _settings(omitted=omitted)

    with pytest.raises(ValueError) as excinfo:
        create_confirm_app(settings)

    message = str(excinfo.value)
    assert omitted in message, message
    # The message must be actionable, not just correct: an operator reading a
    # crash loop needs the environment variable name, not the field name.
    assert "POSTERN_APP_ASSERTION" in message, message


def test_a_complete_assertion_config_builds() -> None:
    """The negative above is only worth something if the positive holds."""
    assert create_confirm_app(_settings(), device_key_store=no_enrolled_devices()) is not None


def test_for_testing_builds_an_app_that_authenticates_nobody() -> None:
    """``for_testing()`` must not be a back door.

    It supplies three ``.invalid`` values (RFC 2606: the name cannot resolve,
    so no request leaves the machine) rather than a generated key pair. The
    app therefore builds -- every test that wants an app object gets one --
    while the default fixture is one that can authenticate NOBODY. For a
    service whose finding was that it authenticated everybody, that is the
    direction the default belongs in.

    It supplies no device key store at all, which is why this call passes
    ``no_enrolled_devices()`` explicitly: since 2026-09-24 an app that cannot
    verify an approval signature does not build, and the fixture that enrols
    nobody is named at the call site rather than defaulted into existence.
    Both halves say the same thing -- this app authenticates nobody and can
    approve nothing.
    """
    settings = ConfirmSettings.for_testing()
    assert settings.app_assertion_jwks_uri is not None
    assert settings.app_assertion_issuer is not None
    assert settings.app_assertion_audience is not None
    assert create_confirm_app(settings, device_key_store=no_enrolled_devices()) is not None


def test_the_test_audience_is_not_the_api_services_audience() -> None:
    """``services/api/settings.py`` defaults ``audience`` to ``"postern"``.

    If a deployment gave this service that same value and both trusted one
    issuer, a customer token good enough to list a balance would be good
    enough to approve a payment, and the read/write split would be void at
    the identity layer while still holding at the signing layer. Nothing in
    this process can check that -- the other service is a separate deployment
    with a separate environment, and ``.importlinter`` forbids reading its
    settings from here. What this pins is only that the fixture does not
    quietly teach the collision.
    """
    assert ConfirmSettings.for_testing().app_assertion_audience != "postern"


# ---------------------------------------------------------------------------
# 2. Default deny, enumerated against the app's real route table.
# ---------------------------------------------------------------------------


def _routes(app: Starlette) -> list[tuple[str, str]]:
    """Every (method, path) the assembled app actually serves.

    Read off ``app.routes`` rather than written down here, which is the whole
    point: a route added to this service tomorrow appears in this list without
    anyone updating this file, and has to be either declared public in
    ``PUBLIC_PATHS`` or denied without a bearer.
    """
    found: list[tuple[str, str]] = []
    for route in app.routes:
        path = getattr(route, "path", None)
        methods = getattr(route, "methods", None)
        if path is None or methods is None:
            continue
        for method in sorted(methods - {"HEAD", "OPTIONS"}):
            found.append((method, path))
    return sorted(found)


def _concrete(path: str) -> str:
    """Fill path parameters so the route can actually be requested."""
    return re.sub(r"\{[^}]+\}", "placeholder", path)


async def test_every_non_public_route_denies_an_unauthenticated_caller(app: Starlette) -> None:
    """The finding, expressed as a property over the whole route table.

    Not "the two routes I remember are protected" but "every route this app
    serves is protected unless it is on the published public list". The list
    of routes is derived from the app; the list of exemptions is a constant a
    reviewer can see change in a diff.
    """
    protected = [(m, p) for m, p in _routes(app) if p not in PUBLIC_PATHS]
    assert protected, "no protected routes found -- the route table changed shape"

    async with client(app) as c:
        for method, path in protected:
            response = await c.request(method, _concrete(path), json={"signature": "x"})
            assert response.status_code == 401, (method, path, response.status_code)
            assert response.json() == {
                "error": "invalid_token",
                "error_description": "a verified app assertion is required",
            }, (method, path)


async def test_the_public_routes_stay_reachable_without_a_bearer(app: Starlette) -> None:
    """The other half: default-deny must not have taken the device grant out.

    ``/device_authorization`` and ``/token`` are polled by the BROWSER, which
    holds no credential at all -- that is the premise of RFC 8628, not an
    oversight. If a later change "secures" them, this fails and the person
    making that change has to argue for it.
    """
    async with client(app) as c:
        for method, path in _routes(app):
            if path not in PUBLIC_PATHS:
                continue
            response = await c.request(method, _concrete(path), json={})
            assert response.status_code != 401, (method, path)


async def test_an_unknown_path_is_401_and_not_404(app: Starlette) -> None:
    """Default deny runs before routing, so it covers paths that do not exist.

    A 404 here would confirm which paths are absent and, by elimination, which
    are present -- free reconnaissance against the service that holds the
    write key. Being outermost means the router never gets the chance to
    answer, so an unauthenticated scan learns only that it is unauthenticated.
    """
    async with client(app) as c:
        for path in ("/nonexistent", "/admin", "/.env", "/challenges"):
            response = await c.post(path, json={})
            assert response.status_code == 401, (path, response.status_code)


def test_the_public_path_list_is_exactly_these_nine() -> None:
    """Adding a tenth must be a deliberate, reviewed act.

    ``PUBLIC_PATHS`` is the single exemption list for the whole service. A
    change to it is a change to what the write path serves anonymously, and it
    should never happen as a side effect of some other edit. The five
    ``/verify`` entries are the browser's pairing page, and
    ``dev-docs/decisions/0021-public-html-on-the-write-key-service.md`` is
    where serving them here was decided. ``/session/jwks.json`` is the
    session key's public half, which ``services/api``'s verifier fetches.
    """
    assert PUBLIC_PATHS == {
        "/.well-known/jwks.json",
        "/session/jwks.json",
        "/device_authorization",
        "/token",
        "/verify",
        "/verify/qr.svg",
        "/verify/state",
        "/verify.js",
        "/verify.css",
    }


def test_every_public_path_is_a_route_with_methods(app: Starlette) -> None:
    """A public path the route table does not serve with ``.methods`` would be
    skipped by the table-driven tests above, which is how a ``StaticFiles``
    mount would have slipped past both of them."""
    served = {path for _, path in _routes(app)}
    assert set(PUBLIC_PATHS) <= served, set(PUBLIC_PATHS) - served


# ---------------------------------------------------------------------------
# 3. Every way a token can be wrong is the same 401.
# ---------------------------------------------------------------------------

PROTECTED = "/challenges/chal_probe/approve"


def _bad_headers(key_pair: RSAKeyPair) -> dict[str, dict[str, str]]:
    other = RSAKeyPair.generate()
    return {
        "no header": {},
        "empty credential": {"Authorization": "Bearer"},
        "blank credential": {"Authorization": "Bearer   "},
        "wrong scheme": {"Authorization": "Basic Y3VzdDpwdw=="},
        "no scheme": {
            "Authorization": key_pair.create_token(
                subject=CUSTOMER, issuer=ISSUER, audience=AUDIENCE, expires_in_seconds=60
            )
        },
        "malformed jwt": {"Authorization": "Bearer not.a.jwt"},
        "garbage": {"Authorization": "Bearer " + "A" * 400},
        "wrong issuer": bearer(key_pair, issuer="https://evil.invalid"),
        "wrong audience": bearer(key_pair, audience="postern"),
        "no audience": bearer(key_pair, audience=None),
        "expired": bearer(key_pair, expires_in_seconds=-30),
        "signed by another key": bearer(other),
        "no exp": raw_bearer(key_pair, claims_now(exp=None)),
        "exp beyond the maximum lifetime": bearer(key_pair, expires_in_seconds=3600),
        "iat in the future": raw_bearer(
            key_pair, claims_now(iat=int(time.time()) + 10 * ASSERTION_CLOCK_SKEW_SECONDS)
        ),
        "nbf in the future": raw_bearer(
            key_pair, claims_now(nbf=int(time.time()) + 10 * ASSERTION_CLOCK_SKEW_SECONDS)
        ),
        "nbf not a number": raw_bearer(key_pair, claims_now(nbf="soon")),
    }


async def test_every_bad_token_produces_the_identical_401(
    app: Starlette, key_pair: RSAKeyPair
) -> None:
    """One body for every failure mode.

    An attacker probing a deployment must not be able to separate "your
    audience is wrong" from "your signature is wrong" and walk the difference
    to a working token. ``JWTVerifier.load_access_token`` already collapses
    all of these to ``None``, so this asserts the shape is carried up rather
    than reconstructed differently per branch.
    """
    bodies: dict[str, tuple[int, str]] = {}
    async with client(app) as c:
        for label, headers in _bad_headers(key_pair).items():
            response = await c.post(PROTECTED, json={"signature": "x"}, headers=headers)
            bodies[label] = (response.status_code, response.text)

    assert {status for status, _ in bodies.values()} == {401}, bodies
    assert len({text for _, text in bodies.values()}) == 1, bodies


async def test_the_401_carries_www_authenticate(app: Starlette) -> None:
    """RFC 6750 §3. A client that gets a bare 401 with no challenge cannot
    tell "re-authenticate" from "this endpoint is broken"."""
    async with client(app) as c:
        response = await c.post(PROTECTED, json={"signature": "x"})
    assert response.status_code == 401
    assert response.headers["www-authenticate"].startswith("Bearer")


async def test_a_token_with_no_subject_is_refused(app: Starlette, key_pair: RSAKeyPair) -> None:
    """A verified token that names nobody must not become an anonymous pass.

    ``AccessToken.subject`` is ``str | None``, so a verifier can hand back a
    valid token with no ``sub``. Everything downstream derives the customer
    from that value; ``None`` or empty has to stop here rather than arrive at
    a handler as a falsy customer.
    """
    token = key_pair.create_token(
        subject="", issuer=ISSUER, audience=AUDIENCE, expires_in_seconds=60
    )
    async with client(app) as c:
        response = await c.post(
            PROTECTED, json={"signature": "x"}, headers={"Authorization": f"Bearer {token}"}
        )
    assert response.status_code == 401


async def test_a_verifier_that_raises_is_a_401_and_not_a_500(app: Starlette) -> None:
    """A JWKS fetch that throws must not open the door, nor look like a bug.

    ``load_access_token`` catches its own failures, but the fetch beneath it
    can raise on DNS, TLS or a timeout. A 500 from an endpoint whose whole job
    is to be unreachable without a valid assertion is not a refusal: it is an
    outage that an operator may well "fix" by relaxing something.
    """

    class _Exploding:
        async def verify_token(self, token: str) -> Any:
            raise RuntimeError("JWKS endpoint unreachable")

    exploding = create_confirm_app(
        ConfirmSettings.for_testing(),
        assertion_verifier=_Exploding(),
        device_key_store=no_enrolled_devices(),
    )
    async with client(exploding) as c:
        response = await c.post(
            PROTECTED, json={"signature": "x"}, headers={"Authorization": "Bearer anything"}
        )
    assert response.status_code == 401


# ---------------------------------------------------------------------------
# 4. What the middleware hands the handler.
# ---------------------------------------------------------------------------


async def test_a_valid_assertion_reaches_the_handler_with_its_body_intact(
    app: Starlette, key_pair: RSAKeyPair
) -> None:
    """The middleware must not consume the request body.

    It reads ``scope["headers"]`` rather than building a ``Request`` for
    exactly this reason: awaiting ``receive()`` here would drain the body and
    leave the handler parsing an empty one. The tell would be a handler
    reporting a missing field that the caller did send, which is a confusing
    bug to chase, so it gets a test rather than only a comment.
    """
    async with client(app) as c:
        response = await c.post(
            "/approve",
            json={"user_code": "ABC-DEF"},
            headers=bearer(key_pair),
        )

    # Past the middleware, into the handler, which parsed the body and looked
    # the code up. Any 4xx about a MISSING field would mean the body was eaten.
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_grant"


def test_verified_subject_is_none_without_middleware() -> None:
    """The handler-side backstop, checked directly.

    Every protected handler calls ``verified_subject`` and returns 401 on
    ``None``. That branch is unreachable through the assembled app, which is
    why it is worth a test of its own: it fires when a handler runs WITHOUT
    the middleware -- a future route table that forgets to wire it, or a unit
    test calling the handler directly. Both are how an authentication control
    quietly stops applying.
    """
    from starlette.requests import Request

    from services.confirm.auth import verified_subject

    bare = Request({"type": "http", "method": "POST", "path": "/x", "headers": []})
    assert verified_subject(bare) is None

    seeded = Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/x",
            "headers": [],
            "state": {ASSERTION_STATE_KEY: AppAssertion(subject=CUSTOMER, claims={})},
        }
    )
    assert verified_subject(seeded) == CUSTOMER


def test_a_forged_state_value_of_the_wrong_type_is_not_a_subject() -> None:
    """``verified_subject`` type-checks what it finds rather than trusting it.

    ``scope["state"]`` is a plain dict that anything in the ASGI chain can
    write to. A middleware or test that put a bare string under this key would
    otherwise produce a truthy "subject" that never went through a verifier.
    """
    from starlette.requests import Request

    from services.confirm.auth import verified_subject

    forged = Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/x",
            "headers": [],
            "state": {ASSERTION_STATE_KEY: "cust_attacker"},
        }
    )
    assert verified_subject(forged) is None


async def test_non_http_scopes_pass_through() -> None:
    """Lifespan must not be answered with a 401.

    ``AppAssertionMiddleware`` is the outermost thing on this app, so it sees
    the lifespan scope too. Refusing it would break startup on any real ASGI
    server while every test that drives the app directly kept passing.
    """
    seen: list[str] = []

    async def inner(scope: Any, receive: Any, send: Any) -> None:
        seen.append(scope["type"])

    class _NeverCalled:
        async def verify_token(self, token: str) -> Any:  # pragma: no cover
            raise AssertionError("the verifier must not run for a lifespan scope")

    async def receive() -> Any:  # pragma: no cover - never awaited
        raise AssertionError("receive must not be touched for a lifespan scope")

    async def send(message: Any) -> None:  # pragma: no cover - never awaited
        raise AssertionError("send must not be touched for a lifespan scope")

    middleware = AppAssertionMiddleware(inner, verifier=_NeverCalled(), max_lifetime_seconds=300)
    await middleware({"type": "lifespan"}, receive, send)
    assert seen == ["lifespan"]


# ---------------------------------------------------------------------------
# 5. An assertion must expire, soon, and must not be minted in the future.
# ---------------------------------------------------------------------------
#
# fastmcp 4.0.3's ``JWTVerifier.load_access_token`` checks ``exp`` only when
# the claim is present and never reads ``iat`` or ``nbf``. So an assertion
# minted without ``exp`` stayed good forever at ``POST /scan``,
# ``POST /approve`` and the challenge approval callback. These pin the check
# ``AppAssertionMiddleware`` makes after the verifier has accepted a token.


async def _status(app: Starlette, headers: dict[str, str]) -> int:
    """POST ``/approve`` with a well-formed body and return the status.

    401 is the middleware refusing. 400 ``invalid_grant`` is the handler
    looking the code up and not finding it, which only happens past the
    middleware, so it stands for "the assertion was accepted".
    """
    async with client(app) as c:
        response = await c.post("/approve", json={"user_code": "ABC-DEF"}, headers=headers)
    return response.status_code


def _app_with_max_lifetime(key_pair: RSAKeyPair, seconds: int) -> Starlette:
    verifier = JWTVerifier(public_key=key_pair.public_key, issuer=ISSUER, audience=AUDIENCE)
    return create_confirm_app(
        dataclasses.replace(
            ConfirmSettings.for_testing(), app_assertion_max_lifetime_seconds=seconds
        ),
        assertion_verifier=verifier,
        device_key_store=no_enrolled_devices(),
    )


async def test_an_assertion_with_no_exp_is_refused(app: Starlette, key_pair: RSAKeyPair) -> None:
    """The verifier accepts it; the middleware must not."""
    assert await _status(app, raw_bearer(key_pair, claims_now(exp=None))) == 401


async def test_an_assertion_with_a_boolean_exp_is_refused(
    app: Starlette, key_pair: RSAKeyPair
) -> None:
    """``True`` is an ``int`` to Python and ``1`` to the verifier's comparison.

    The verifier reads it as a timestamp in 1970 and refuses it as expired, so
    this is pinned for the middleware's own type check rather than because the
    verifier lets it through today.
    """
    assert await _status(app, raw_bearer(key_pair, claims_now(exp=True))) == 401


async def test_an_exp_beyond_the_default_maximum_lifetime_is_refused(
    app: Starlette, key_pair: RSAKeyPair
) -> None:
    """``create_token``'s own default of 3600 seconds is past the 300-second default."""
    assert await _status(app, bearer(key_pair, expires_in_seconds=3600)) == 401


async def test_an_iat_in_the_future_beyond_the_skew_is_refused(
    app: Starlette, key_pair: RSAKeyPair
) -> None:
    future = int(time.time()) + ASSERTION_CLOCK_SKEW_SECONDS + 60
    assert await _status(app, raw_bearer(key_pair, claims_now(iat=future))) == 401


async def test_an_iat_that_is_not_a_number_is_refused(app: Starlette, key_pair: RSAKeyPair) -> None:
    """Present and unreadable is not the same as absent."""
    assert await _status(app, raw_bearer(key_pair, claims_now(iat="now"))) == 401


async def test_an_nbf_in_the_future_beyond_the_skew_is_refused(
    app: Starlette, key_pair: RSAKeyPair
) -> None:
    future = int(time.time()) + ASSERTION_CLOCK_SKEW_SECONDS + 60
    assert await _status(app, raw_bearer(key_pair, claims_now(nbf=future))) == 401


@pytest.mark.parametrize("nbf", ["soon", True, float("nan"), float("inf"), [1]])
async def test_an_nbf_that_is_not_a_finite_number_is_refused(
    app: Starlette, key_pair: RSAKeyPair, nbf: Any
) -> None:
    """Present and unreadable is not the same as absent."""
    assert await _status(app, raw_bearer(key_pair, claims_now(nbf=nbf))) == 401


async def test_an_nbf_now_or_in_the_past_passes(app: Starlette, key_pair: RSAKeyPair) -> None:
    now = int(time.time())
    assert await _status(app, raw_bearer(key_pair, claims_now(nbf=now))) == 400
    assert await _status(app, raw_bearer(key_pair, claims_now(nbf=now - 3600))) == 400


async def test_an_nbf_inside_the_skew_passes(app: Starlette, key_pair: RSAKeyPair) -> None:
    nbf = int(time.time()) + ASSERTION_CLOCK_SKEW_SECONDS // 2
    assert await _status(app, raw_bearer(key_pair, claims_now(nbf=nbf))) == 400


async def test_a_short_lived_assertion_passes(app: Starlette, key_pair: RSAKeyPair) -> None:
    assert await _status(app, bearer(key_pair, expires_in_seconds=60)) == 400


async def test_an_assertion_with_no_iat_but_a_short_exp_passes(
    app: Starlette, key_pair: RSAKeyPair
) -> None:
    """``iat`` is checked only when present; ``exp`` is the claim that is required."""
    assert await _status(app, raw_bearer(key_pair, claims_now(iat=None))) == 400


async def test_an_iat_inside_the_skew_passes(app: Starlette, key_pair: RSAKeyPair) -> None:
    """A backend clock a few seconds ahead of this one is not an attack."""
    now = int(time.time())
    claims = claims_now(iat=now + ASSERTION_CLOCK_SKEW_SECONDS // 2, exp=now + 60)
    assert await _status(app, raw_bearer(key_pair, claims)) == 400


async def test_the_configured_maximum_lifetime_is_the_one_enforced(
    key_pair: RSAKeyPair,
) -> None:
    """The setting reaches the middleware: at 60 seconds, 30 passes and 150 does not."""
    app = _app_with_max_lifetime(key_pair, 60)
    assert await _status(app, bearer(key_pair, expires_in_seconds=30)) == 400
    too_far = 60 + ASSERTION_CLOCK_SKEW_SECONDS + 60
    assert await _status(app, bearer(key_pair, expires_in_seconds=too_far)) == 401


async def test_a_lifetime_refusal_logs_the_path_and_no_claim(
    app: Starlette, key_pair: RSAKeyPair, caplog: pytest.LogCaptureFixture
) -> None:
    """The same log shape as the other refusals: the path, never a claim value."""
    with caplog.at_level(logging.WARNING, logger="services.confirm.auth"):
        assert await _status(app, raw_bearer(key_pair, claims_now(exp=None))) == 401
    messages = [r.getMessage() for r in caplog.records if r.name == "services.confirm.auth"]
    assert messages, "the refusal was not logged"
    assert all(m.startswith("confirm: /approve rejected,") for m in messages), messages
    assert all(CUSTOMER not in m for m in messages), messages

"""Inbound authentication for the write path (audit findings C-01, C-02).

WHY THIS EXISTS. Until this module landed, ``services/confirm`` authenticated
nobody. ``main.py`` built ``Starlette(routes=routes)`` with no ``middleware=``
argument at all, against the five ``services/api/main.py`` wires, and a grep
for ``Authorization`` across ``services/confirm/*.py`` found exactly one hit,
an OUTBOUND header in ``execute.py``. Three unauthenticated calls --
``POST /device_authorization``, then ``POST /approve`` naming any customer in
a JSON body, then ``POST /token`` -- ended in a token signed with the WRITE
key, ``aud=payments.svc``, ``scope=payments:execute``. The same absence let
anyone holding a challenge id approve it at
``POST /challenges/{challenge_id}/approve``, and that id travels back through
the model's channel into a third-party vendor's chat history.

WHAT AUTHENTICATES NOW. The operator's banking-app backend mints a
short-lived assertion; the app presents it as ``Authorization: Bearer``. This
service verifies it against that backend's JWKS with ``iss`` and ``aud`` both
checked, and every protected handler takes the customer from the verified
``sub``. Never from the request body. CLAUDE.md states the rule for the read
path -- "Never accept ``user_id`` as a tool argument ... A user identifier the
model can set is a direct object reference an agent can be talked into
changing" -- and a write-path request body is the same shape of input with
more at stake, since what sits at the end of this path is money movement
rather than a masked balance.

WHY A SIGNED ASSERTION AND NOT mTLS OR A MESH-SET HEADER. CLAUDE.md: "Do not
cite network isolation as a zero-trust control. PrivateLink is blast-radius
reduction. The identity layer is the control." A header an Istio sidecar sets
is also unverifiable here: this repository has no mesh, so such a control
could not be tested at all, only asserted. A JWT is checkable in process
against a generated key pair, which is what ``tests/test_confirm_auth.py``
does.

THE AUDIENCE MUST NOT BE THE API SERVICE'S. ``services/api/settings.py``
defaults ``audience`` to ``"postern"`` for the CUSTOMER tokens third-party AI
clients present. If a deployment points ``POSTERN_APP_ASSERTION_AUDIENCE`` at
that same value and both services trust the same issuer, then a token good
enough to list a balance is also good enough to approve a payment, and the
read/write split that the whole architecture rests on is void at the identity
layer even though the key split still holds at the signing layer. There is no
guard for that here and there cannot be one: the two services are separate
processes with separate environments, and ``.importlinter`` forbids this
module from reading ``services.api``'s settings to compare. It is an operator
requirement, recorded here because this is where a reader will look.

DEFAULT DENY. ``AppAssertionMiddleware`` protects every route except the ones
``PUBLIC_PATHS`` names explicitly. A route added to this service tomorrow is
therefore authenticated by omission rather than unauthenticated by omission,
which is the direction the audit found this service pointing.

UNIFORM 401. Missing header, wrong scheme, malformed JWT, expired, wrong
issuer, wrong audience and bad signature all produce the identical body. The
caller learns that it is not authenticated and nothing else; an attacker
probing configuration cannot separate "your audience is wrong" from "your
signature is wrong" and walk the difference. ``JWTVerifier.load_access_token``
already collapses every one of those into ``None``, so this is the shape the
verifier hands up rather than a shape this module went out of its way to
flatten.

AN ASSERTION MUST EXPIRE, and the verifier does not make it. fastmcp 4.0.3
checks ``exp`` only when present and never reads ``iat``, so until
2026-09-30 an assertion minted without ``exp`` authorised money movement
forever. ``_lifetime_refusal`` now refuses one with no numeric ``exp``, one
whose ``exp`` is further ahead than ``POSTERN_CONFIRM_ASSERTION_MAX_LIFETIME_SECONDS``
allows, one whose ``iat`` is in the future, and one whose ``nbf`` is unreadable or in
the future, each with the same 401.
"""

from __future__ import annotations

import logging
import math
import time
from typing import Any, Protocol, TypeGuard

from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

logger = logging.getLogger(__name__)

#: Where the verified assertion lands in the ASGI ``scope["state"]`` dict, and
#: therefore what ``request.state.<this>`` reads. Starlette's
#: ``HTTPConnection.state`` is a view over ``scope["state"]``, so middleware
#: and handler agree on one dict without either importing the other.
ASSERTION_STATE_KEY = "postern_app_assertion"

#: How far this process's clock may lag the app backend's before an
#: assertion's ``iat`` counts as "in the future", and how far past
#: ``POSTERN_CONFIRM_ASSERTION_MAX_LIFETIME_SECONDS`` its ``exp`` may sit for
#: the same reason. Both clocks are servers', the minter is the operator's app
#: backend and not the phone, and NTP keeps two servers well inside one
#: second, so 30 seconds is slack for a drifting host rather than a normal
#: operating margin. It is also the most extra life a future-dated assertion
#: can buy: an attacker holding the app backend's key could mint one a few
#: seconds ahead, never an hour ahead.
ASSERTION_CLOCK_SKEW_SECONDS = 30

#: The field default of ``ConfirmSettings.app_assertion_max_lifetime_seconds``
#: and the ceiling ``from_env`` refuses above. `services/confirm/settings.py`
#: carries why each number is what it is.
DEFAULT_ASSERTION_MAX_LIFETIME_SECONDS = 300
MAX_ASSERTION_MAX_LIFETIME_SECONDS = 3600

#: The only paths served without an app assertion. Everything else is denied
#: by default. Each entry owes a reason:
#:
#: ``/.well-known/jwks.json``
#:     Publishes the PUBLIC half of the write signing key. It is meant to be
#:     fetched by anything that verifies this service's outbound tokens, and
#:     ``services/confirm/jwks.py`` is the reason it carries no private
#:     material.
#:
#: ``/device_authorization``
#:     RFC 8628 §3.1. The browser calls this BEFORE any identity exists --
#:     that is the entire premise of the device grant -- so there is no
#:     assertion it could present. It returns a freshly generated
#:     ``device_code``/``user_code`` pair bound to no customer.
#:
#: ``/token``
#:     RFC 8628 §3.4, polled by the same browser, which still holds no
#:     credential. Requiring an assertion here would be a category error: the
#:     bank app holds the assertion, the browser holds the ``device_code``,
#:     and they are different parties by design. The ``device_code`` is the
#:     authority at this endpoint -- 43 characters from
#:     ``secrets.token_urlsafe(32)``, so 256 bits -- and since the write token
#:     was deleted from this endpoint's response (audit finding C-01), the
#:     most it can yield is one layer-1 session for the customer who approved
#:     that exact code on their own phone. A refresh presents the refresh
#:     token it issued, which is the credential there.
#: THE FIVE BELOW ARE THE PAIRING PAGE, added 2026-09-30, and all five are
#: the BROWSER again: it opened ``verification_uri_complete`` and holds no
#: assertion. None sets a cookie or reads one, and every other path on this
#: service authenticates with a bearer assertion and never a cookie, so a
#: page served here has no ambient credential to borrow.
#: ``dev-docs/decisions/0021-public-html-on-the-write-key-service.md`` is why
#: this service and not ``services/api`` serves them.
#:
#: ``/verify``
#:     The page a browser opens from ``verification_uri_complete``; the
#:     browser holds no assertion. It shows only what the stored row says.
#:
#: ``/verify/qr.svg``
#:     The image the page embeds. Refused unless ``Sec-Fetch-Site`` is
#:     ``same-origin``, so another site cannot embed it.
#:
#: ``/verify/state``
#:     The status the page's script polls, refused the same way.
#:
#: ``/verify.js``
#:     The page's only script, same-origin so the page's CSP needs no inline
#:     script.
#:
#: ``/verify.css``
#:     The page's only stylesheet, so ``style-src 'self'`` has a target.
#:
#: ``/session/jwks.json``
#:     The PUBLIC half of the session key, which signs the layer-1 access
#:     tokens ``POST /token`` issues. ``services/api``'s verifier fetches it
#:     holding no assertion, which is why it is here; like the write set above
#:     it carries no private material (``services/confirm/jwks.py``).
PUBLIC_PATHS = frozenset(
    {
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
)


class VerifiedToken(Protocol):
    """The part of ``fastmcp``'s ``AccessToken`` this module reads.

    A structural type rather than the concrete class so the tests can hand in
    a stub without constructing a pydantic model, and so this module does not
    grow an import of the ``mcp`` SDK's provider module alongside the
    ``fastmcp`` one (CLAUDE.md: mixing the two produces confusing type
    errors).
    """

    @property
    def subject(self) -> str | None: ...

    @property
    def claims(self) -> dict[str, Any] | None: ...


class AssertionVerifier(Protocol):
    """What ``AppAssertionMiddleware`` needs from a token verifier.

    ``fastmcp.server.auth.providers.jwt.JWTVerifier`` satisfies it, which is
    the point: this is the same class ``services/api/server.py`` constructs
    for customer tokens, so both services check tokens through one
    implementation and a bug fixed in it is fixed on both paths.
    """

    async def verify_token(self, token: str) -> VerifiedToken | None: ...


class AppAssertion:
    """A verified banking-app assertion.

    ``subject`` is the ``sub`` claim AFTER verification. It is the only place
    a protected handler may read the customer from; the request body is not a
    source of identity on this service.
    """

    __slots__ = ("claims", "subject")

    def __init__(self, subject: str, claims: dict[str, Any]) -> None:
        self.subject = subject
        self.claims = claims


def _unauthenticated() -> JSONResponse:
    """The one 401 body every failure mode produces.

    ``WWW-Authenticate`` per RFC 6750 §3. The body shape matches
    ``services/confirm/device_auth.py::_error`` and
    ``services/confirm/callback.py::_error`` so a client parses one error
    shape across this whole service.
    """
    return JSONResponse(
        status_code=401,
        content={
            "error": "invalid_token",
            "error_description": "a verified app assertion is required",
        },
        headers={"WWW-Authenticate": 'Bearer error="invalid_token"'},
    )


def _bearer(scope: Scope) -> str | None:
    """The bearer credential from the ASGI headers, or ``None``.

    Reads ``scope["headers"]`` rather than building a ``Request`` because this
    runs before the handler and must not touch ``receive``: draining the body
    here would leave nothing for the handler to read.
    """
    for name, value in scope.get("headers", []):
        if name.lower() != b"authorization":
            continue
        try:
            header = value.decode("latin-1")
        except UnicodeDecodeError:  # pragma: no cover - ASGI servers pre-validate
            return None
        scheme, _, credential = header.partition(" ")
        if scheme.lower() != "bearer":
            return None
        credential = credential.strip()
        return credential or None
    return None


def _is_time(value: Any) -> TypeGuard[int | float]:
    """A JSON number that can be a NumericDate (RFC 7519 §2).

    ``bool`` is excluded by name because it is an ``int`` subclass: ``True``
    would otherwise pass as the second after the epoch. NaN and the
    infinities are excluded because every comparison against NaN is false,
    which would let one through the checks below that are written as "refuse
    if greater than".
    """
    if isinstance(value, bool) or not isinstance(value, int | float):
        return False
    return math.isfinite(value)


def _lifetime_refusal(claims: dict[str, Any], *, now: float, max_lifetime: int) -> str | None:
    """Why this verified assertion must still be refused, or ``None``.

    ``JWTVerifier.load_access_token`` in fastmcp 4.0.3 checks ``exp`` only
    when the claim is present (``if exp is not None and exp < time.time()``)
    and never reads ``iat`` or ``nbf``. An assertion minted without ``exp``
    therefore verified forever, and this assertion is what authorises
    ``POST /scan``, ``POST /approve`` and the challenge approval callback.
    The checks sit here, after the verifier, rather than in a subclass of it,
    so ``services/api`` and this service keep checking tokens through one
    unmodified implementation.

    Four refusals. The returned string goes into the log line and never a
    claim value, which is the shape every other refusal here logs:

    - ``exp`` absent or not a number.
    - ``exp`` more than ``max_lifetime`` plus ``ASSERTION_CLOCK_SKEW_SECONDS``
      ahead of now. The verifier has already refused one in the past. Without
      ``iat`` required, "lifetime" can only be measured as time left, so this
      bounds how long a token captured this second stays usable.
    - ``iat`` present and either not a number or more than
      ``ASSERTION_CLOCK_SKEW_SECONDS`` ahead of now. Absent ``iat`` is
      accepted: RFC 7519 makes it optional and ``exp`` already bounds the
      token's remaining life.

    - ``nbf`` present and either not a finite number or more than
      ``ASSERTION_CLOCK_SKEW_SECONDS`` ahead of now. Absent ``nbf`` is
      accepted, as absent ``iat`` is. A past ``nbf`` is not a refusal.
    """
    exp = claims.get("exp")
    if not _is_time(exp):
        return "assertion carries no numeric exp"
    if exp - now > max_lifetime + ASSERTION_CLOCK_SKEW_SECONDS:
        return "assertion exp is beyond the maximum lifetime"
    if "iat" in claims:
        iat = claims["iat"]
        if not _is_time(iat) or iat - now > ASSERTION_CLOCK_SKEW_SECONDS:
            return "assertion iat is not a number or is in the future"
    if "nbf" in claims:
        nbf = claims["nbf"]
        if not _is_time(nbf) or nbf - now > ASSERTION_CLOCK_SKEW_SECONDS:
            return "assertion nbf is not a number or is not yet valid"
    return None


class AppAssertionMiddleware:
    """Default-deny bearer verification for the write path.

    Pure ASGI rather than a ``BaseHTTPMiddleware`` subclass, matching
    ``services/api/asgi/``'s two: ``BaseHTTPMiddleware`` wraps the request in
    an anyio task group and a streaming response, neither of which this needs,
    and both of which change how an exception from a handler surfaces.

    Ordering note: this is the outermost thing on the confirm app, so an
    unauthenticated request never reaches a handler, never opens a database
    session and never touches the device code store. That matters beyond
    tidiness -- ``POST /challenges/{id}/approve`` mutates challenge state on
    the expired path before it would ever have consulted a caller's identity.
    """

    def __init__(
        self, app: ASGIApp, *, verifier: AssertionVerifier, max_lifetime_seconds: int
    ) -> None:
        # Required rather than defaulted, so a caller that forgets it fails at
        # assembly instead of silently getting a lifetime nobody configured.
        # `ConfirmSettings.from_env` bounds the value an operator can set;
        # this refuses the one a caller in code could still pass.
        if not 1 <= max_lifetime_seconds <= MAX_ASSERTION_MAX_LIFETIME_SECONDS:
            raise ValueError(
                f"max_lifetime_seconds must be between 1 and "
                f"{MAX_ASSERTION_MAX_LIFETIME_SECONDS}, got {max_lifetime_seconds}"
            )
        self.app = app
        self.verifier = verifier
        self.max_lifetime_seconds = max_lifetime_seconds

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")
        if path in PUBLIC_PATHS:
            await self.app(scope, receive, send)
            return

        credential = _bearer(scope)
        if credential is None:
            logger.warning("confirm: %s rejected, no bearer assertion presented", path)
            await _unauthenticated()(scope, receive, send)
            return

        # `JWTVerifier.load_access_token` catches its own failures and returns
        # `None`. The `except` is for what it does not catch -- a JWKS fetch
        # raising, say -- because an exception escaping here would become a
        # 500 from an endpoint whose whole job is to be unreachable without a
        # valid assertion, and a 500 is not a refusal.
        try:
            verified = await self.verifier.verify_token(credential)
        except Exception:
            logger.warning("confirm: %s rejected, assertion verification raised", path)
            await _unauthenticated()(scope, receive, send)
            return

        if verified is None or not verified.subject:
            logger.warning("confirm: %s rejected, assertion invalid or carries no sub", path)
            await _unauthenticated()(scope, receive, send)
            return

        claims = dict(verified.claims or {})
        refusal = _lifetime_refusal(claims, now=time.time(), max_lifetime=self.max_lifetime_seconds)
        if refusal is not None:
            logger.warning("confirm: %s rejected, %s", path, refusal)
            await _unauthenticated()(scope, receive, send)
            return

        state = scope.setdefault("state", {})
        state[ASSERTION_STATE_KEY] = AppAssertion(
            subject=verified.subject,
            claims=claims,
        )
        await self.app(scope, receive, send)


def verified_subject(request: Request) -> str | None:
    """The verified ``sub``, or ``None`` if this request was never verified.

    Every protected handler calls this and returns 401 on ``None``. In the
    assembled app that branch is unreachable, because
    ``AppAssertionMiddleware`` already refused the request -- which is exactly
    why the branch is worth keeping. It fires when a handler runs WITHOUT the
    middleware: a future route table that forgets to wire it, or a unit test
    that calls the handler directly. Both of those are how an authentication
    control quietly stops applying, and both fail closed here instead.
    """
    assertion = request.scope.get("state", {}).get(ASSERTION_STATE_KEY)
    if not isinstance(assertion, AppAssertion):
        return None
    return assertion.subject


def verified_claims(request: Request) -> dict[str, Any]:
    """Every claim of the verified assertion, or ``{}`` if none was verified.

    The companion to ``verified_subject`` above, split out rather than folded
    into it because the two have different failure contracts.
    ``verified_subject`` returns ``None`` so a handler can fail closed on it;
    this one returns an EMPTY DICT, because no claim it carries is ever an
    authorization input. Its one reader is
    ``services/confirm/audit.py::_client_id``, which asks for ``client_id``
    then ``azp`` to record WHICH client called, and a missing claim there is a
    NULL column, not a refusal.

    Returning ``{}`` rather than ``None`` therefore keeps that reader from
    having to decide what an absent assertion means: on this service it cannot
    happen except in the same handler-without-middleware case
    ``verified_subject`` already fails closed on, and that branch returns 401
    before anything asks for claims.
    """
    assertion = request.scope.get("state", {}).get(ASSERTION_STATE_KEY)
    if not isinstance(assertion, AppAssertion):
        return {}
    return assertion.claims


def unauthenticated_response() -> JSONResponse:
    """The 401 a handler returns when ``verified_subject`` gives ``None``.

    Shared with the middleware so the two cannot drift into two different
    401 bodies for the same condition.
    """
    return _unauthenticated()

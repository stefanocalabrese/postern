"""RFC 8628 device authorization endpoints for the confirm service.

Endpoints:
- ``POST /device_authorization`` — Generate device code + QR pairing data.
- ``POST /token`` with ``grant_type=device_code`` — The browser's poll.
  Returns an error until the mobile app approves, then a layer-1 session:
  an access token for this deployment's MCP server and a refresh token (see
  "WHAT ``/token`` RETURNS" below).
- ``POST /scan`` -- Mobile app scan of the QR (binds the pairing to the first
  customer who presents a current rotation token).
- ``POST /approve`` — Mobile app approval callback (marks device code as
  approved).

The confirm service is the right home for these because:
1. It holds the SESSION key, which signs the layer-1 access token and
   nothing else (``services/confirm/session_token.py``), and publishes its
   public half at ``/session/jwks.json`` for ``services/api`` to verify.
2. The approval callback needs to update device code state, which lives in
   the same service as the token endpoint.

Two URIs, where there used to be one. ``verification_uri_complete`` is the
PAGE the AI client shows its user: ``verification_uri`` plus ``?d=`` and the
pairing's display handle, 128 random bits that key the page and nothing else.
The QR on that page encodes the APP LINK instead: ``device_app_link_uri`` plus
the ``user_code`` and a two-second rotation token. ``device_code`` is in
neither, because it is the only credential ``POST /token`` asks for, and
anything in a QR is readable over a shoulder or a screen share.

Pairing code (``user_code``): 6 uppercase alphanumeric chars, displayed as
XXX-XXX on both surfaces. ``POST /approve`` takes it and nothing else that
names the pairing, looks the pairing up by it, and approves only if the same
customer scanned it first (``postern_core.auth.device_codes`` records which
half of the A2 control that is and which half only the operator's app can
perform).

WHO IS AUTHENTICATED, AND WHO IS NOT. ``POST /scan`` and ``POST /approve``
are the banking app, which must present a bearer assertion the operator's app
backend minted; ``services/confirm/auth.py`` verifies it and this module
takes the customer from the verified ``sub``. ``POST /device_authorization``
and ``POST /token`` are the BROWSER, which by the device grant's premise
holds no credential at all, and they are named in that module's
``PUBLIC_PATHS`` with the reason.

WHO CAN BE CUT, AND WHERE (ZT-7). All three endpoints that know a customer
refuse a revoked one: ``POST /scan`` and ``POST /approve`` on the assertion's
``sub``, before the device code is touched, and ``POST /token`` on the
``customer_ref`` stored on the device code, before anything is issued.
Nothing is keyed on ``DeviceCode.client_id`` -- the browser supplies it
unauthenticated at ``POST /device_authorization``, so a kill switch enforced
on it would be theatre. ``services/confirm/revocation.py`` holds the full
argument.

WHAT THIS MODULE NO LONGER DOES. It used to take the customer identity from
``/approve``'s request body (``subject_value``) and it used to return a
WRITE-signed token from ``/token``. Together those made three unauthenticated
calls sufficient to obtain ``aud=payments.svc scope=payments:execute`` for any
customer named in a JSON body. Both are gone: the identity comes from a
verified assertion, and ``/token`` returns no write token. A write token is
minted inside the approval path in ``services/confirm/callback.py``, where it
is used and discarded, and is never serialized to an HTTP client.

WHAT ``/token`` RETURNS: for an approved, unexpired code whose customer is
not revoked, a layer-1 access token (``aud`` = the MCP server, 600 seconds,
signed with the SESSION key) and a ``prt1.`` refresh token, the code spent in
the same compare-and-set that records the family. Before 30 September 2026 it
returned a read token with ``aud=accounts.svc``, ``scope=accounts:read`` and
``act.sub=svc:postern``, signed with the READ key: a layer-2 backend token,
which handoff §7.1 keeps apart from layer 1 because under Vault both services
signed with transit key ``postern-read`` and any client that completed a
pairing held a token the accounts backend accepts. From then until the
session token landed it answered 503 and issued nothing
(``DETAIL_ISSUANCE_DISABLED``, historical now). ``dev-docs/device-grant-session-token-spec.md``
is the contract.

That is also why ``device_auth_routes`` takes no ``write_minter`` any more.
Nothing on the device grant path signs with the write key, so this module is
not handed it — the key split is better expressed by not passing the key than
by passing it and not using it.

Usage in ``main.py``::

    from services.confirm.device_auth import (
        device_auth_routes,
        build_device_code_store,
    )

    store = build_device_code_store(settings)
    routes = device_auth_routes(store=store, settings=settings)
"""

from __future__ import annotations

import asyncio
import dataclasses
import hmac
import logging
import time
import uuid
from collections import OrderedDict
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from postern_core.auth.device_codes import (
    DeviceCode,
    DeviceCodeStoreBase,
    DeviceCodeStoreContended,
    DeviceCodeStoreFull,
    ScanClaim,
    create_device_code_store,
)
from postern_core.auth.refresh_sessions import (
    MAX_GENERATIONS,
    RefreshSession,
    RefreshSessionStoreBase,
    RefreshSessionStoreContended,
    RefreshSessionStoreFull,
    Rotation,
    canonical_scope,
    hash_refresh_token,
    ms_of,
    new_refresh_token,
    new_sid,
    sid_of,
)
from postern_core.auth.resource_uri import normalize_resource
from postern_core.auth.revocation import RevocationStoreBase, RevocationStoreUnavailable
from postern_core.identity import CustomerRef
from postern_core.json_strict import loads_finite
from postern_core.log_safety import describe_exception, exc_info_for_log
from postern_core.risk.pairing_network import (
    MatchResult,
    NetworkEnricher,
    NetworkFacts,
    NetworkRelation,
    classify,
    compare_facts,
    normalised_address,
    pairing_network_signal,
    sanitised,
)
from postern_core.risk.types import signal_to_json
from postern_core.store.engine import Database
from pydantic import ValidationError
from redis.exceptions import RedisError
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from services.confirm.audit import (
    DETAIL_ALREADY_APPROVED,
    DETAIL_ALREADY_SCANNED,
    DETAIL_CLIENT_ID_MISMATCH,
    DETAIL_DEVICE_CODE_SPENT,
    DETAIL_INVALID_SUBJECT,
    DETAIL_ISSUED_BEFORE_REVOCATION,
    DETAIL_NOT_SCANNED,
    DETAIL_QR_INVALID,
    DETAIL_QR_STALE,
    DETAIL_RECALL_LOCAL_ONLY,
    DETAIL_RECALL_NO_SESSION,
    DETAIL_REFRESH_REUSED,
    DETAIL_REVOKED,
    DETAIL_SCAN_CONFLICT,
    DETAIL_SCANNED_BY_OTHER,
    DETAIL_SCOPE_EXCEEDED,
    DETAIL_SESSION_EXPIRED,
    DETAIL_SESSION_GENERATIONS_EXHAUSTED,
    DETAIL_SESSION_REVOKED,
    DETAIL_STORED_IDENTITY_MALFORMED,
    DETAIL_USER_CODE_NOT_FOUND,
    RECALL_TOOL_NAME,
    REFRESH_TOOL_NAME,
    SCAN_ROUTE,
    SCAN_TOOL_NAME,
    TOKEN_ROUTE,
    TOKEN_TOOL_NAME,
    PairingAudit,
    device_code_handle,
    pairing_client_ip,
)
from services.confirm.auth import unauthenticated_response, verified_claims, verified_subject
from services.confirm.qr_token import QrVerdict, slot_at, verify_token
from services.confirm.revocation import (
    customer_revoked,
    customer_revoked_since,
    log_refusal,
    revocation_store,
    revoked_response,
    store_unavailable_response,
)
from services.confirm.session_token import (
    ACCESS_TOKEN_LIFETIME_SECONDS,
    SessionTokenMinter,
)
from services.confirm.settings import DEFAULT_DEVICE_SCOPES, ConfirmSettings

logger = logging.getLogger(__name__)

#: How many successful scans per process may be waiting on the pairing network
#: enricher at once. A scan that finds every slot taken does not wait: it
#: records ``"unknown"`` for both matches and logs ``saturated``.
#:
#: A CODE CONSTANT, NOT A SETTING, because the number is a bound and not a
#: tuning knob. It exists for a provider that is slow but cooperative: without
#: it every successful scan during a provider stall parks a task for the whole
#: budget, and the per-address and per-customer scan limits bound each caller,
#: not their sum. With it at most eight scans per replica ever wait, and a
#: provider that ignores cancellation and keeps its slots eventually holds all
#: eight, after which every scan records ``"unknown"`` at once instead of
#: piling on. A healthy local-database provider answers far inside the budget,
#: so eight are exhausted only by eight scans arriving within one lookup's
#: duration. It is no defence against a provider that never yields: that one
#: blocks the loop before the semaphore matters.
PAIRING_ENRICHMENT_SLOTS = 8

#: The ``client_id`` a pairing may not declare. ``services/api``'s risk
#: middleware uses ``-`` for "no client on this token", so a pairing named
#: ``-`` would share one risk budget and one revocation key with every token
#: that carries none. Spelled here rather than imported, because
#: ``.importlinter`` forbids this service from reading ``services.api``.
RESERVED_CLIENT_ID = "-"

#: RFC 6749 section 5.1: "The authorization server MUST include the HTTP
#: "Cache-Control" response header field [RFC2616] with a value of "no-store"
#: in any response containing tokens ... as well as the "Pragma" response
#: header field [RFC2616] with a value of "no-cache"." On every ``/token``
#: response, not only the ones that carry a token.
TOKEN_RESPONSE_HEADERS = {"Cache-Control": "no-store", "Pragma": "no-cache"}

_TOKEN_HEADER_NAMES = frozenset(name.lower().encode("latin-1") for name in TOKEN_RESPONSE_HEADERS)
_TOKEN_HEADERS_RAW = [
    (name.lower().encode("latin-1"), value.encode("latin-1"))
    for name, value in TOKEN_RESPONSE_HEADERS.items()
]


class TokenResponseHeaders:
    """Stamp ``TOKEN_RESPONSE_HEADERS`` on every response for ``/token``.

    Pure ASGI, and installed by ``create_confirm_app`` OUTSIDE Starlette's
    ``ServerErrorMiddleware`` (amended 1 October 2026), because the
    ``token_endpoint`` wrapper only reaches answers the handler writes. Three
    answers on this path never pass through it: the address-bucket limiter's
    refusal, the body limit's 413 and the 500 ``ServerErrorMiddleware`` sends
    for an unhandled exception. Spec section 5 puts both headers on "every
    other ``/token`` response", so they are set here, on the
    ``http.response.start`` message, replacing any value already present.
    Every other path passes through untouched.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope.get("path") != TOKEN_ROUTE:
            await self.app(scope, receive, send)
            return

        async def stamped(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = [
                    (name, value)
                    for name, value in message.get("headers", [])
                    if name.lower() not in _TOKEN_HEADER_NAMES
                ]
                message = {**message, "headers": headers + _TOKEN_HEADERS_RAW}
            await send(message)

        await self.app(scope, receive, stamped)


#: How far this process's clock may disagree with Redis's when an approval
#: (written on this clock) is compared with a customer revocation stamp
#: (written on Redis's), in milliseconds. It errs toward refusal: a customer
#: whose approval lands within two seconds after a revocation re-pairs.
APPROVAL_CLOCK_TOLERANCE_MS = 2_000

#: How often one family's unknown-hash presentations may reach the log, per
#: process, and how many families the limiter remembers (oldest evicted).
UNKNOWN_REFRESH_LOG_INTERVAL_SECONDS = 60
UNKNOWN_REFRESH_LOG_ENTRIES = 4_096

#: What the refresh-family store raises when it cannot answer: redis-py's
#: errors, a socket error, a timeout. The refresh grant answers each with a
#: retryable 503 (or, where the family is refused anyway, with the refusal);
#: anything else is a fault, propagates and is a 500.
SESSION_STORE_OUTAGES: tuple[type[Exception], ...] = (RedisError, OSError, TimeoutError)

#: The same types for the device-code store, which is the same Redis (or the
#: same process) behind ``POSTERN_REDIS_URL``. Its own name so a reader of the
#: device grant's ``/token`` path is not sent to the refresh family's store.
DEVICE_STORE_OUTAGES = SESSION_STORE_OUTAGES

# ---------------------------------------------------------------------------
# Error responses — RFC 8628 §3.3 and §3.4 error codes.
# ---------------------------------------------------------------------------


def _error(status: int, code: str, description: str) -> JSONResponse:
    """Return an RFC 8628-compatible error response."""
    return JSONResponse(
        status_code=status,
        content={
            "error": code,
            "error_description": description,
        },
    )


def _unredeemable_response() -> JSONResponse:
    """The one answer ``POST /token`` gives for a code it will not redeem.

    THREE BRANCHES SHARE IT, AND THAT IS THE CONTROL. A code this store never
    held, a code a previous exchange spent, and a code a concurrent exchange is
    spending all get this response, byte for byte, so nothing in a status or a
    body tells a caller that a value it presented ever existed, was approved,
    or belonged to anybody. Returning it from one function rather than
    assembling it at three call sites is what keeps that true as any of the
    three is edited.

    WHAT IS WITHHELD HERE IS RECORDED ELSEWHERE. The distinction the caller
    does not get is exactly the distinction an operator needs, so it lives in
    ``audit_log.detail`` -- ``device_code_not_found`` against
    ``device_code_spent`` -- where the party holding the code cannot read it.
    The module already takes this shape for ``access_denied``, which
    deliberately cannot be told apart from a customer declining on their phone.

    ``invalid_grant`` IS THE HONEST CODE, and RFC 8628 §3.5 leaves no better
    one. Its own four codes are ``authorization_pending``, ``slow_down``,
    ``access_denied`` and ``expired_token``: the first two are the only ones
    the RFC tells a client to keep polling through, so neither can be used
    here without making a browser loop until the code's TTL runs out;
    ``expired_token`` is false, because a spent code has not reached its
    expiry; and ``access_denied`` says the authorization was refused, when it
    was granted and then used. That leaves RFC 6749 §5.2, whose
    ``invalid_grant`` covers a grant that "is invalid, expired, revoked, does
    not match the redirection URI used in the authorization request, or was
    issued to another client" -- and §3.5 makes every code other than the two
    polling ones terminal, so the browser stops and starts a fresh pairing,
    which is the only recovery that exists.

    THE DESCRIPTION IS TRUE OF ALL THREE, which it was not before 2026-09-26:
    it read "device code not found or already revoked", and a spent code is
    neither. A response the caller cannot act on differently is no reason to
    describe it wrongly.
    """
    return _error(400, "invalid_grant", "device code cannot be redeemed")


def _store_full_response(retry_after: int) -> JSONResponse:
    """The 503 ``POST /device_authorization`` answers when it cannot create a code.

    Two causes share it: the store is full, and every freshly generated
    ``user_code`` or display handle collided with a live one
    (``DeviceCodeStoreContended``). The browser can do nothing different for
    either, so it gets one body; only ``Retry-After`` differs.

    THE SAME SHAPE AND THE SAME ARGUMENT AS
    `services/confirm/revocation.py`'s ``store_unavailable_response``, which
    already chose ``temporarily_unavailable`` with a 503 for the one other
    condition on this path that is neither the caller's fault nor terminal.
    RFC 6749 §4.1.2.1 vocabulary rather than a §5.2 token-endpoint code,
    stated rather than glossed: no §5.2 code means "come back", and inventing
    a private one would be worse. The browser here holds no credential, has
    done nothing wrong, and the honest signal for it is one it can retry.

    ``Retry-After`` carries the device code lifetime for a full store, because
    that is the interval after which capacity is guaranteed to have been
    released: the oldest code in a full store expires within one TTL, and
    ``create_device_code`` sweeps before it refuses. For exhausted generation
    it carries the poll interval, because a fresh draw needs no code to
    expire first.

    NOT ``access_denied`` and NOT a 429. ``access_denied`` is terminal and
    would end every pairing attempt during a capacity event, dressing an
    availability failure as a security decision. A 429 would say the CALLER
    sent too many, which is false for the customer who arrives during someone
    else's flood -- and it is `services/confirm/rate_limit.py`'s code, kept
    distinct so an operator reading logs can tell "this caller is being
    limited" from "the service is full".
    """
    return JSONResponse(
        status_code=503,
        content={
            "error": "temporarily_unavailable",
            "error_description": (
                "the service cannot start a new device pairing right now; retry shortly"
            ),
        },
        headers={"Retry-After": str(retry_after)},
    )


# ---------------------------------------------------------------------------
# Device authorization endpoint — POST /device_authorization.
# ---------------------------------------------------------------------------


async def device_authorization(request: Request) -> JSONResponse:
    """Generate a device code and return QR pairing data.

    Request body (application/x-www-form-urlencoded or JSON):
        client_id: OAuth client identifier (required).
        scopes: Space-separated scope list (optional, defaults to all read).

    Response (200):
        device_code: Opaque code for token exchange.
        user_code: Human-readable pairing code (XXX-XXX).
        verification_uri: Base URI for the verification page.
        verification_uri_complete: The pairing page, ``verification_uri`` plus
            ``d=`` and the display handle. Never the ``user_code`` and never
            the ``device_code``.
        expires_in: Lifetime in seconds.
        interval: Seconds between token polls.

    RFC 8628 §3.1 — the device_code is 40+ chars, user_code is 6+ chars
    of uppercase alphanumeric (no ambiguous characters).

    Response (503): the device code store is at its cap, or every generated
    pairing code or display handle collided with a live one. See
    ``_store_full_response``.

    WHAT THIS HANDLER STORES FROM AN UNAUTHENTICATED BODY, and why both
    fields are now checked. ``client_id`` and ``scopes`` are copied verbatim
    onto a row kept for the code's whole life, and until 2026-09-24 neither
    was bounded or even type-checked. That made the per-row cost a caller's
    choice: 1,633 bytes for a realistic code, 65,560 for one padded to the
    body limit. `services/confirm/settings.py` carries the measurement and
    the ceilings.

    The type check is not decoration. ``await request.json()`` hands back
    whatever JSON contains, so ``{"scopes": [0, 0, ...]}`` put a Python list
    on a field annotated ``str`` -- and 24,000 bytes of that JSON parse to
    67,252 bytes of objects, so the byte-counting body limit in front of this
    service was never a bound on what the store holds. The same ``isinstance``
    guard, for the same reason, is already in ``approve_callback`` below.

    THIS ENDPOINT WRITES NO ``audit_log`` ROW, ON ANY BRANCH, AND THAT IS A
    DECISION. It was reviewed on 2026-09-26, when ``POST /approve`` and
    ``POST /token`` both gained one and this one deliberately did not.

    It resolves no identity. The browser is in
    ``services/confirm/auth.py``'s ``PUBLIC_PATHS`` because by the device
    grant's premise it holds no credential at all, so there is no ``sub``,
    there is no customer, and ``client_id`` is a string the caller chose --
    which is the same reason ``services/confirm/revocation.py`` refuses to key
    a kill switch on it. ``services/confirm/audit.py``'s ``PairingAudit``
    carries the rule that makes that decisive rather than merely true: a row
    is owed when the server resolved an identity AND concluded something about
    its authority, and creating a device code is neither half. Every row this
    endpoint could write would carry NULL in ``customer_ref`` and
    ``no_access_token`` in ``customer_ref_absence_reason`` -- one value,
    constant across the endpoint's entire population, which is a column that
    tells a reader nothing.

    And it would be one INSERT per unauthenticated request. Nothing
    authenticates in front of this handler: what bounds it is
    ``rate_limit_device_authorization``, 60 a minute per address bucket, and
    an address bucket is not an identity. Under decision 0006 an audit write
    that fails fails the request, so a row here would additionally mean that
    no pairing can BEGIN while the audit store is merely slow -- bought for a
    row naming nobody, on the one device grant endpoint of the four that
    resolves no identity whatsoever.

    WHAT IS INVISIBLE BECAUSE OF THIS, stated plainly. Device code creation.
    An attacker can mint codes against any ``client_id`` they like and this
    table will not show it. What bounds that population is
    ``max_device_codes`` (10,000, and ``DeviceCodeStoreFull`` refuses rather
    than evicting) and the address bucket above; what records the refusals is
    the ``logger.warning`` below. The admission is narrower than it first
    reads: a code that is ever approved appears on the pairing row by its
    handle, and one that is ever exchanged appears again on the token row, so
    the population no row names is exactly the codes that touched nobody.
    """
    settings: ConfirmSettings = request.app.state.settings

    # Parse form or JSON body.
    #
    # WRAPPED, unlike every version of this handler before 2026-09-24. This
    # is a public endpoint and ``await request.json()`` sat bare: ``{not
    # json`` raised ``JSONDecodeError`` and a JSON array raised
    # ``AttributeError`` from ``.get`` on a list, both 500s from an endpoint
    # that owes a 400. The identical defect was fixed one file over in
    # `services/confirm/callback.py`; leaving this one because it is
    # technically a different function is how the write path ended up with
    # three copies of ``_scrub``.
    content_type = request.headers.get("content-type", "")
    if "application/json" in content_type:
        # `loads_finite`, not `request.json()`: `NaN`, `Infinity` and a literal
        # like `1e999` are refused as a body that is not JSON. `ValueError`
        # covers the decode error, bad UTF-8 and that refusal alike, and
        # `RecursionError` (a `RuntimeError`) is a body nested past the limit.
        try:
            body = loads_finite(await request.body())
        except (ValueError, RecursionError):
            return _error(400, "invalid_request", "body must be JSON")
        if not isinstance(body, dict):
            return _error(400, "invalid_request", "body must be a JSON object")
    else:
        form = await request.form()
        body = dict(form)

    client_id = body.get("client_id", "")
    # The same string it always was, now named in `services/confirm/settings.py`
    # so that `MIN_SCOPES_LENGTH` -- the floor under ``max_scopes_length`` --
    # can be its length rather than a copy of its length.
    scopes = body.get("scopes", DEFAULT_DEVICE_SCOPES)

    if not isinstance(client_id, str) or not isinstance(scopes, str):
        return _error(400, "invalid_request", "client_id and scopes must be strings")

    if not client_id:
        return _error(400, "invalid_request", "client_id is required")
    if client_id == RESERVED_CLIENT_ID:
        return _error(400, "invalid_request", "client_id '-' is reserved")

    # REJECTED, never truncated. Truncating would silently store a different
    # ``client_id`` than the caller sent and a different scope set than the
    # caller asked for, and both are values a later control could key on.
    # ``invalid_scope`` is RFC 6749 §5.2 vocabulary for the scope half.
    if len(client_id) > settings.max_client_id_length:
        return _error(
            400,
            "invalid_request",
            f"client_id exceeds {settings.max_client_id_length} characters",
        )
    if len(scopes) > settings.max_scopes_length:
        return _error(
            400,
            "invalid_scope",
            f"scopes exceeds {settings.max_scopes_length} characters",
        )

    store: DeviceCodeStoreBase = request.app.state.device_code_store

    try:
        code: DeviceCode = await store.create_device_code(
            client_id=client_id,
            scopes=scopes,
            verification_uri=settings.device_verification_uri,
            expires_in=settings.device_code_ttl_seconds,
            interval=settings.device_poll_interval_seconds,
            # READ BY `POST /scan`, which compares it with the scanner's
            # address and records the relation on the scan's audit row. It
            # lives only on this row, for the pairing's lifetime. Under the
            # default of zero trusted hops this is the direct peer, which
            # behind a load balancer is the balancer's address on both sides
            # of that comparison, so the relation then means nothing.
            creator_ip=pairing_client_ip(request, settings.trusted_proxy_hops),
        )
    except DeviceCodeStoreFull as exc:
        logger.warning(
            "device authorization refused: the device code store holds %d codes, its cap",
            exc.held,
        )
        return _store_full_response(settings.device_code_ttl_seconds)
    except DeviceCodeStoreContended as exc:
        # Five draws all taken is a generator problem, not bad luck, so it is
        # logged; the browser did nothing wrong and a retry draws again.
        logger.warning("device authorization refused: %s", exc)
        return _store_full_response(settings.device_poll_interval_seconds)

    return JSONResponse(
        status_code=200,
        content={
            "device_code": code.device_code,
            "user_code": code.user_code_display,
            "verification_uri": code.verification_uri,
            "verification_uri_complete": code.verification_uri_complete,
            "expires_in": settings.device_code_ttl_seconds,
            "interval": settings.device_poll_interval_seconds,
        },
    )


# ---------------------------------------------------------------------------
# Token endpoint — POST /token with grant_type=device_code.
# ---------------------------------------------------------------------------


#: RFC 8628 section 3.4's required ``grant_type`` for the device-code poll.
#: ``token_endpoint`` also accepts the short literal ``device_code`` it has
#: always served, and maps both to ``_DEVICE_CODE_GRANT`` once, so nothing
#: downstream of the dispatch can see which spelling arrived.
_DEVICE_CODE_GRANT_URN = "urn:ietf:params:oauth:grant-type:device_code"
_DEVICE_CODE_GRANT = "device_code"
_REFRESH_GRANT = "refresh_token"
_GRANT_TYPES = {
    _DEVICE_CODE_GRANT: _DEVICE_CODE_GRANT,
    _DEVICE_CODE_GRANT_URN: _DEVICE_CODE_GRANT,
    _REFRESH_GRANT: _REFRESH_GRANT,
}

#: Which ``app.state`` attribute holds which poll-time map. Two maps, not one,
#: so the last PENDING poll never paces the first poll after approval: a
#: browser that polled at t and whose customer approved at t+1 gets its answer
#: at t+2, not ``slow_down``.
_PENDING_POLLS = "_poll_times"
_APPROVED_POLLS = "_approved_poll_times"


def _poll_times(request: Request, which: str = _PENDING_POLLS) -> dict[str, datetime]:
    """Per-device-code time of the last paced poll, for RFC 8628 ``slow_down``.

    ``which`` picks the map: pending polls, or polls of an approved, unspent
    code (paced since 2026-09-30, see ``_paced``). Keyed by the raw device
    code and never leaves the process: not logged, not serialised. Only codes
    the store holds are ever recorded, and entries are swept once older than
    ``device_code_ttl_seconds`` (see ``_paced``), so each map is bounded by
    the live-code population.
    """
    poll_times: dict[str, datetime] | None = getattr(request.app.state, which, None)
    if poll_times is None:
        poll_times = {}
        setattr(request.app.state, which, poll_times)
    return poll_times


def _drop_poll_time(request: Request, device_code_value: str) -> None:
    _poll_times(request, _PENDING_POLLS).pop(device_code_value, None)
    _poll_times(request, _APPROVED_POLLS).pop(device_code_value, None)


def _paced(
    request: Request, which: str, device_code_value: str, settings: ConfirmSettings
) -> JSONResponse | None:
    """``slow_down`` if this code was polled within the interval, else record the poll.

    Pop first so the dict stays ordered by last poll, then sweep from the
    front: nothing outlives the code's TTL, and the sweep is amortised O(1)
    per poll.
    """
    poll_times = _poll_times(request, which)
    last_poll = poll_times.get(device_code_value)
    if last_poll is not None:
        elapsed = (datetime.now(UTC) - last_poll).total_seconds()
        if elapsed < settings.device_poll_interval_seconds:
            return _error(
                400,
                "slow_down",
                f"Poll again in {int(settings.device_poll_interval_seconds - elapsed)}s",
            )
    now = datetime.now(UTC)
    poll_times.pop(device_code_value, None)
    poll_times[device_code_value] = now
    horizon = now - timedelta(seconds=settings.device_code_ttl_seconds)
    while True:
        oldest = next(iter(poll_times))
        if poll_times[oldest] >= horizon:
            break
        del poll_times[oldest]
    return None


async def token_endpoint(request: Request) -> JSONResponse:
    """``POST /token``, every answer carrying ``TOKEN_RESPONSE_HEADERS``.

    A wrapper so no exit can forget the two headers RFC 6749 section 5.1
    requires: `_token_response` answers, this stamps.
    """
    response = await _token_response(request)
    response.headers.update(TOKEN_RESPONSE_HEADERS)
    return response


def _resource_refusal(form: Any, settings: ConfirmSettings) -> JSONResponse | None:
    """400 ``invalid_target`` for a ``resource`` this deployment does not serve.

    RFC 8707 section 2. Absent is accepted. Present, it must occur once and,
    in `postern_core.auth.resource_uri`'s normal form, equal the access
    token's audience; a fragment, a relative reference and a repeat are all
    ``invalid_target`` ("The requested resource is invalid, missing, unknown,
    or malformed"). Request shape only, so no row.
    """
    values = form.getlist("resource")
    if not values:
        return None
    presented = values[0] if len(values) == 1 and isinstance(values[0], str) else None
    normalized = normalize_resource(presented) if presented is not None else None
    if normalized is None or normalized != settings.session_token_audience:
        return _error(400, "invalid_target", "the requested resource is not served here")
    return None


async def _token_response(request: Request) -> JSONResponse:
    """Answer a device-code poll, and record every answer that names a customer.

    AN APPROVED CODE IS WORTH ONE SESSION. An approved, unexpired, unspent
    code for a customer who is not revoked gets a layer-1 access token and a
    refresh token (spec section 5 of
    ``dev-docs/device-grant-session-token-spec.md``), and the code is spent in
    the same compare-and-set that records which family it created. Before
    30 September 2026 this endpoint returned a layer-2 read token
    (``aud=accounts.svc``), and between then and the session token it issued
    nothing (``DETAIL_ISSUANCE_DISABLED``).

    ONE APPROVED CODE IS WORTH ONE TOKEN. Until 2026-09-26 it was worth every
    token a caller cared to ask for until the code expired: this handler minted
    and returned without marking the code, and the 5-second poll interval is
    enforced only while a code is UNAPPROVED, so an approved one was bounded by
    `services/confirm/rate_limit.py`'s 300 requests a minute per address bucket
    and by nothing else. A read token lives 60 seconds and a device code 900,
    so fifteen exchanges a minute apart bought uninterrupted account-read
    access for a leaked code's whole remaining life. RFC 8628 does not require
    this to be closed -- it says nothing either way, which is why
    ``dev-docs/decisions/0012-device-code-single-use.md`` exists and what it
    argues from.

    Handles ``grant_type=device_code`` and RFC 8628 §3.4's
    ``urn:ietf:params:oauth:grant-type:device_code``, which are one grant, and
    ``grant_type=refresh_token``. Any other value is a 404.

    Request body:
        grant_type: "device_code" or the RFC 8628 URN (required for this path).
        device_code: The opaque device code from /device_authorization.
        resource: Optional, RFC 8707; see `_resource_refusal`.

    Response while pending (400):
        {"error": "authorization_pending", "error_description": "..."}

    Response after approval (200):
        {"access_token": "...", "token_type": "Bearer", "expires_in": 600,
         "refresh_token": "prt1.<sid>.<secret>", "scope": "<canonical scopes>"}

    There is no layer-2 token in that response and there must never be one: not
    a ``write_token`` (audit finding C-01) and not the read token this
    endpoint returned until 2026-09-30. The access token's audience is this
    deployment's MCP server and its key signs nothing else, so no domain
    service accepts it. The write path mints its own token inside
    ``services/confirm/callback.py``, per request, and never hands one out.

    Error codes per RFC 8628 §3.4:
        authorization_pending — not yet approved, keep polling.
        slow_down — client is polling too fast (adds 5s to interval). Since
            2026-09-30 also answered to an approved, unspent code polled
            within the interval, because two retryable 503s remain: the
            revocation store's outage and a full refresh-family store.
        access_denied — user explicitly denied on mobile app, OR the customer
            who approved this code has been revoked (ZT-7). The two are
            deliberately indistinguishable here; see the comment at the check.
        expired_token — device code has passed its TTL.

    And three that are RFC 6749 §5.2's or RFC 8707's, because RFC 8628 has
    no code for them:
        invalid_grant -- the code is unknown, or spent (by an earlier exchange,
            or by a concurrent one that won the claim). One body for all
            three, so the response is not an oracle; ``_unredeemable_response``
            above carries why this code and not one of the four.
        temporarily_unavailable -- the revocation store could not be
            consulted, or the refresh-family store is full. Both answer 503
            with ``Retry-After`` set to the poll interval and spend nothing.
        invalid_target -- a ``resource`` this deployment does not serve.

    WHAT IS RECORDED, AND HOW LITTLE OF IT. This endpoint wrote no
    ``audit_log`` row until 2026-09-26, which left the device grant's chain
    with a hole in the middle. It now writes exactly one row on each of SIX
    exits -- the mint, a ZT-7 refusal (now, or since the approval), a stored
    identity that will not parse, a revocation store that could not answer, a
    full refresh-family store, and a spent code (a replay, or a lost claim)
    -- plus one for any exception ``_exchange`` raises, and nothing on the
    other nine: a wrong grant type, an unserved ``resource``, a missing
    ``device_code``, an unknown code, an expired code, ``slow_down`` on a
    pending code, ``slow_down`` on an approved one, ``authorization_pending``,
    and an approved code with no customer on it.

    RE-COUNTED WITH THE LAYER-1 SESSION TOKEN, from the exits of this
    function, ``_paced``, `_resource_refusal` and ``_exchange`` together,
    which is the only way to count them. The issuance refusal went and the
    mint came back; the full family store and the lost claim are new
    recorded exits (the lost claim under the spent-code detail it shares);
    the ``resource`` refusal is a new unrecorded one. Six recorded, nine not.

    EVERY UNRECORDED EXIT IS ONE THAT RESOLVED NOBODY, and that is the rule
    rather than a list: ``services/confirm/audit.py``'s ``PairingAudit`` owes a
    row only where the server resolved an identity and then decided something
    about its authority. ``customer_ref`` is read off the device code AFTER the
    grant type, the code lookup, the expiry check, the approval check and the
    pacing check, so a wrong grant type, a missing or unknown ``device_code``,
    an expired code, either ``slow_down`` and ``authorization_pending`` are all
    answered before any identity exists. That is what keeps this table from
    becoming a log of a browser waiting: at the configured 5-second interval
    and 900-second lifetime a poll loop can run 180 times and write nothing
    while pending, and at most one row per interval once approved while a
    503 is being retried. The empty-``customer_ref`` exit is the one that
    reads the field and finds nobody, and it is logged instead.

    NOTHING OF A TOKEN GOES INTO A ROW: not the string, not a segment of it,
    not a digest. The row carries the family's ``session_id``, which every
    access token of the family carries anyway.
    """
    at = datetime.now(UTC)
    started = time.monotonic()

    form = await request.form()
    try:
        grant_type = _form_value(form, "grant_type") or ""
    except MalformedParameter as exc:
        return _error(400, "invalid_request", str(exc))

    # EXACT lookup, no case folding and no trimming: the URN and the literal
    # become one canonical value here, and any other string is refused.
    canonical = _GRANT_TYPES.get(grant_type)
    if canonical == _REFRESH_GRANT:
        return await _refresh_grant(request, form, at=at, started=started)
    if canonical != _DEVICE_CODE_GRANT:
        # Neither grant this endpoint serves. A 404, where RFC 6749 section
        # 5.2's error responses are 400; kept as it was (spec, Discrepancies).
        return _error(
            404,
            "unsupported_grant_type",
            "only the device_code and refresh_token grants are supported",
        )

    try:
        device_code_value = _form_value(form, "device_code") or ""
    except MalformedParameter as exc:
        return _error(400, "invalid_request", str(exc))
    if not device_code_value:
        return _error(400, "invalid_request", "device_code is required")

    store: DeviceCodeStoreBase = request.app.state.device_code_store
    settings: ConfirmSettings = request.app.state.settings

    # AHEAD OF THE LOOKUP: request shape only, so it resolves nobody and
    # writes no row.
    unserved = _resource_refusal(form, settings)
    if unserved is not None:
        return unserved

    # A STORE OUTAGE here resolved nobody and spent nothing: a retryable 503
    # with the poll interval, and no row.
    try:
        code: DeviceCode | None = await store.get_device_code(device_code_value)
    except DEVICE_STORE_OUTAGES as exc:
        logger.warning("device grant: device-code store unavailable (%s)", type(exc).__name__)
        return store_unavailable_response(settings.device_poll_interval_seconds)
    if code is None:
        # NO ROW, AND THE ASYMMETRY WITH ``POST /approve`` IS DELIBERATE. The
        # same shape one endpoint over IS recorded, as the enumeration signal,
        # because there the caller presented a verified assertion and the row
        # can name whose guess it was. Here the caller holds nothing, so a row
        # would attribute the guess to nobody while letting an
        # unauthenticated party drive an INSERT 300 times a minute per address
        # bucket (``rate_limit_token``).
        return _unredeemable_response()

    if code.is_expired:
        # NO ROW. This runs before the identity is read, so it resolves nobody
        # even for a code that HAD been approved, and it is the ordinary end of
        # every abandoned pairing rather than an event.
        try:
            await store.revoke_device_code(device_code_value)
        except DEVICE_STORE_OUTAGES as exc:
            # Retryable: the next poll finds the code expired again.
            logger.warning(
                "device grant: device-code store unavailable (%s) revoking an expired code",
                type(exc).__name__,
            )
            return store_unavailable_response(settings.device_poll_interval_seconds)
        _drop_poll_time(request, device_code_value)
        return _error(400, "expired_token", "device code has expired")

    # RFC 8628 §3.4 — "slow_down": client is polling faster than the
    # ``interval`` parameter. Enforced while authorization is pending, and
    # since 2026-09-30 also on an approved code that is not spent.
    #
    # WHY APPROVED CODES ARE PACED. The first poll after approval is answered
    # at once (its own map, never paced by the last pending poll) and on
    # success spends the code. What the pacing governs is an approved code
    # that gets a RETRYABLE answer -- the revocation store's outage 503 and a
    # full refresh-family store's 503 -- which a client honouring it would
    # otherwise retry at the address-bucket limiter's pace (300 a minute),
    # each retry costing an ``audit_log`` INSERT and a store read. Paced, it
    # costs one of each per interval. It also cuts a burst of concurrent polls
    # on one approved code within one process to one, before a family is
    # drawn, so orphaned families come only from polls on different replicas.
    #
    # ANSWERED HERE, before ``customer_ref`` is read, so a paced poll writes
    # no row, exactly as the pending ``slow_down`` never has. A SPENT code is
    # not paced: its ``invalid_grant`` is terminal, so there is no retry loop
    # to slow, and a replay stays recorded on every attempt.
    if not code.approved:
        slowed = _paced(request, _PENDING_POLLS, device_code_value, settings)
        if slowed is not None:
            return slowed
        return _error(400, "authorization_pending", "waiting for user approval on mobile app")

    _poll_times(request, _PENDING_POLLS).pop(device_code_value, None)
    if code.exchanged_at is None:
        slowed = _paced(request, _APPROVED_POLLS, device_code_value, settings)
        if slowed is not None:
            return slowed

    # Approved.
    #
    # `customer_ref` is written by `approve_callback` from a VERIFIED
    # assertion `sub` and by nothing else. Reading `client_id` here instead
    # was half of C-01: that field is whatever the caller of
    # `/device_authorization` put in it.
    stored_customer_ref: str = code.customer_ref
    if not stored_customer_ref:
        # NO ROW, because no identity was resolved -- and structurally
        # unreachable, since `approve_callback` writes `approved` and
        # `customer_ref` in ONE store call and nothing else sets either.
        #
        # LOGGED, which it was not before 2026-09-26. A 500 with no row and no
        # log line is the one refusal on this path an operator could not learn
        # about at all, and the condition it reports -- an approved code with
        # no customer on it -- is either a store that lost a field or a writer
        # other than `approve_callback`. Neither is something to find out from
        # a user complaint.
        logger.error(
            "device grant: device code %s is approved with no customer reference; "
            "refusing to mint and writing no audit row, because no identity was resolved",
            device_code_handle(device_code_value),
        )
        return _error(500, "invalid_state", "approval missing customer identity")

    # FROM HERE THE CODE NAMES A CUSTOMER, so every exit below writes exactly
    # one row. Built here rather than at the top of the handler for that
    # reason: this is the first line at which `PairingAudit`'s rule owes one.
    #
    # THE IDENTITY ON THIS ROW IS WEAKER THAN THE PAIRING ROW'S, and a reader
    # comparing the two must know it. At `POST /approve` the customer came
    # from a `sub` on an assertion `AppAssertionMiddleware` verified against a
    # configured JWKS. Here it comes off a stored device code -- written there
    # by that same verified approval, so its PROVENANCE is the assertion -- but
    # the party presenting the code at this endpoint holds no credential
    # beyond the code itself. So the row says "a code approved by this
    # customer was presented", never "this customer asked for it".
    db: Database = request.app.state.postern_database
    audit = PairingAudit(
        db=db,
        call_id=str(uuid.uuid4()),
        at=at,
        started=started,
        subject=stored_customer_ref,
        # NO CLAIMS, so `client_id` is NULL on every row this endpoint writes.
        # There is no OAuth client and no assertion here: the caller is
        # whoever holds the device code. The `client_id` the browser supplied,
        # unauthenticated, at `/device_authorization` goes in
        # `arguments['paired_client_id']` instead -- the same key the pairing
        # row uses, so one predicate returns both halves of a client's
        # onboarding, and it stays out of the column that means "a client this
        # service authenticated".
        claims={},
        client_ip_value=pairing_client_ip(request, settings.trusted_proxy_hops),
        tool_name=TOKEN_TOOL_NAME,
        route=TOKEN_ROUTE,
    )
    audit.names(device_code=device_code_value, paired_client_id=code.client_id)

    try:
        response, detail = await _exchange(request, audit, code=code)
    except Exception as exc:
        # `raise exc from audit_exc`, the shape `approve_callback` and
        # `services/confirm/callback.py` both use: an audit-write failure must
        # not replace the exception that ended the request.
        try:
            await audit.refused(type(exc).__name__)
        except Exception as audit_exc:
            logger.error(
                "audit write failed for a device-grant token exchange after it raised %s: %s",
                type(exc).__name__,
                describe_exception(audit_exc),
                exc_info=exc_info_for_log(audit_exc),
            )
            raise exc from audit_exc
        raise

    # THE ROW IS COMMITTED BEFORE THE RESPONSE IS RETURNED, fail-closed per
    # decision 0006: a raise here drops `response` and the caller gets a 500,
    # so a session no row names never leaves this process. `PairingAudit`'s
    # "FAIL CLOSED AT A MINT" section carries why that order is the right one.
    # Do not move this below the `return`.
    try:
        if detail is None:
            await audit.minted()
        else:
            await audit.refused(detail)
    except Exception as audit_exc:
        logger.error(
            "audit write failed for a device-grant token exchange that answered %d; "
            "failing the request: %s",
            response.status_code,
            describe_exception(audit_exc),
            exc_info=exc_info_for_log(audit_exc),
        )
        raise
    return response


async def _exchange(
    request: Request,
    audit: PairingAudit,
    *,
    code: DeviceCode,
) -> tuple[JSONResponse, str | None]:
    """The checks and the mint, returning ``(response, detail)``.

    ``detail`` is ``None`` for the one exit that issues a session, and
    otherwise one of ``services/confirm/audit.py``'s ``DETAIL_*`` literals or
    an exception's type name. Split out from ``token_endpoint`` so the row is
    written in exactly one place, which is the same division
    ``approve_callback`` and ``services/confirm/callback.py`` both make.

    THE SPENT CHECK COMES FIRST because a code that can never be redeemed
    again must not be answered with a retryable code. Put it after the ZT-7
    check and a replay arriving while the revocation store is down is answered
    503 ``temporarily_unavailable``, which tells the browser to come back for a
    grant no retry will ever redeem.

    THEN THE FAMILY, THEN ZT-7, in spec section 5's order: the family is drawn
    and created BEFORE the code is spent, so a recall at ``POST /scan`` that
    sees the code exchanged always finds the family and its first ``jti``;
    then a customer revoked now, or revoked at or after the approval (step 0,
    which a restore does not undo), checked AFTER the family's ``created_ms``
    is stamped so a revocation landing in between is not lost, and refused by
    discarding the family; then the claim; then the signature.
    """
    if code.exchanged_at is not None:
        return _unredeemable_response(), DETAIL_DEVICE_CODE_SPENT

    try:
        customer = CustomerRef(value=code.customer_ref)
    except ValidationError:
        # Never let this one propagate. `CustomerRef` sets
        # `hide_input_in_errors=True`, which covers `str()` and `repr()` of the
        # exception but NOT its `errors()` output or `.json()` -- both still
        # carry the raw offending value, and an unhandled exception here is
        # logged by whatever sits above us. A fixed string keeps that value out
        # of the log and off the wire.
        #
        # RECORDED, with `customer_ref` NULL and the class of absence in
        # `customer_ref_absence_reason`. The identity WAS resolved -- a
        # non-empty string was read off the code -- and refused, which is what
        # the rule asks for; `DETAIL_STORED_IDENTITY_MALFORMED` carries why it
        # is not `DETAIL_INVALID_SUBJECT`.
        logger.warning("device grant: stored customer reference is not well-formed")
        return (
            _error(500, "invalid_state", "approval identity is not a customer reference"),
            DETAIL_STORED_IDENTITY_MALFORMED,
        )

    settings: ConfirmSettings = request.app.state.settings
    retry_after = settings.device_poll_interval_seconds

    # STEP 1: DRAW the family id, the first refresh token and the access
    # token's claims. The `jti` is drawn here, before anything is written, so
    # the family can name it from its first moment.
    minter: SessionTokenMinter = request.app.state.session_minter
    sessions: RefreshSessionStoreBase = request.app.state.refresh_session_store
    sid = new_sid()
    refresh_token = new_refresh_token(sid)
    scope = canonical_scope(code.scopes)
    claims = minter.prepare(customer=customer, client_id=code.client_id, scope=scope, sid=sid)

    # STEP 2: CREATE THE FAMILY BEFORE THE CODE IS SPENT. A full store leaves
    # the code redeemable and answers a retryable 503, the argument this
    # docstring makes for ZT-7 before the claim. So does a store that cannot
    # answer (amended 1 October 2026): a connection or timeout error is an
    # outage, not a verdict, and a 500 would tell the browser to give up on a
    # pairing the customer approved. A `RefreshSessionCollision` is neither,
    # and still propagates to a 500.
    now = datetime.now(UTC)
    family = RefreshSession(
        sid=sid,
        customer_ref=customer.value,
        client_id=code.client_id,
        scopes=scope,
        created_at=now,
        expires_at=now,
        generation=0,
        current_hash=hash_refresh_token(refresh_token),
        access_tokens=((claims.jti, datetime.fromtimestamp(claims.exp, UTC)),),
        device_code_handle=device_code_handle(code.device_code),
    )
    try:
        await sessions.create(family)
    except RefreshSessionStoreFull as exc:
        logger.warning("device grant: %s; refusing to mint", exc)
        return _session_store_unavailable_response(retry_after), type(exc).__name__
    except SESSION_STORE_OUTAGES as exc:
        logger.warning(
            "device grant: refresh-family store unavailable (%s); refusing to mint",
            type(exc).__name__,
        )
        return _session_store_unavailable_response(retry_after), type(exc).__name__

    # STEP 0 (RUN AFTER STEP 2): ZT-7, AFTER THE FAMILY IS STAMPED. These checks used to run
    # before `create`, which stamps `created_ms` from the store clock. A
    # customer-client revocation stamped S with (the check) < S < `created_ms`
    # was then seen by neither the check nor the refresh comparison
    # (`stamp >= created_ms`, S < created_ms reads as "before the family
    # existed"), and a later restore revived the family for its hour. Run after
    # `create`, every revocation with S < `created_ms` has already executed on
    # the single-threaded store and is seen here; every S >= `created_ms` is
    # caught at refresh. A refusal, an outage or any other raise discards the
    # family just made.
    #
    # ZT-7: refuse the MINT, not only the use.
    #
    # `services/api` would refuse this token on every call anyway, so the
    # practical exposure of minting it is narrow -- but ZT-7's acceptance bar
    # is that a revoked identity stops obtaining access, and handing out a
    # freshly signed token for a customer the operator has cut is obtaining
    # it. Keyed on the customer STORED on the device code, written from a
    # verified assertion at ``POST /approve`` and by nothing else; never on
    # ``code.client_id``, which the browser supplies unauthenticated at
    # ``/device_authorization`` and can set to anything.
    #
    # ``access_denied`` is RFC 8628 §3.5's code for an authorization that was
    # refused, and this endpoint's own docstring already documents it as "user
    # explicitly denied on mobile app". That collision is the point rather
    # than an accident: the browser cannot tell a revocation from the customer
    # declining on their phone, so a party holding only a ``device_code``
    # learns nothing about anyone's revocation state. It holds a code this
    # same customer already approved, so it is not a third party either.
    #
    # The store failing is NOT a denial. `store_unavailable_response` answers
    # 503 so the browser retries rather than treating an outage as a refusal;
    # either way no token is minted, which is the fail-closed half.
    #
    # BOTH OUTCOMES NOW LEAVE A ROW, and the refusal's is the only durable
    # trace either way: this endpoint has no client id to put in a log line
    # the way `services/api/middleware/revocation.py` does, which is exactly
    # what `services/confirm/revocation.py`'s `log_refusal` says. The refusal
    # keeps `DETAIL_REVOKED`, shared with the challenge path and the pairing
    # path, so `WHERE detail = 'revoked'` stays the whole answer to "did my
    # revocation take effect on the write path". The outage records the
    # exception's own type instead, which is how an operator tells an outage
    # from a refusal -- the caller cannot, and must not.
    try:
        revoked = await customer_revoked(request, customer.value)
        # REVOKED SINCE THE APPROVAL (spec section 5 step 0). The approval predates a
        # revocation, so a later restore must not make it redeemable. The one
        # comparison across two clocks -- the approval is this process's, the
        # stamp Redis's -- so it carries `APPROVAL_CLOCK_TOLERANCE_MS` and
        # errs toward refusal.
        stamp = await customer_revoked_since(request, customer.value)
        # THE KILL SWITCH, while it stands (3 October 2026). Keyed on
        # ``code.client_id``, the browser's unauthenticated choice, which is
        # the very value the api's kill switch keys on: refusing here only
        # narrows access, and a client that declares another id gains nothing
        # it did not already have at the api. Claims with ONLY ``client_id``
        # (no ``sub``, ``jti`` or ``iat``) so both stores ask the kill-switch
        # set and nothing else. A restore makes the unspent code redeemable;
        # the family it creates is then issued after the kill.
        killed = await revocation_store(request).is_revoked({"client_id": code.client_id})
    except RevocationStoreUnavailable as exc:
        logger.warning("device grant: revocation store unavailable, refusing to mint")
        await _discard_orphan(sessions, sid, "a revocation store outage")
        return store_unavailable_response(retry_after), type(exc).__name__
    except Exception:
        await _discard_orphan(sessions, sid, "a revocation check that raised")
        raise
    approved_ms = ms_of(code.approved_at) if code.approved_at is not None else 0
    if (
        revoked
        or killed
        or (stamp is not None and stamp >= approved_ms - APPROVAL_CLOCK_TOLERANCE_MS)
    ):
        log_refusal("a device-grant token exchange")
        await _discard_orphan(sessions, sid, "a revocation")
        return _error(400, "access_denied", "authorization was refused"), DETAIL_REVOKED

    # NAMED ONLY ONCE IT EXISTS, so a full-store or outage row never carries
    # the id of a family that was never stored (amended 1 October 2026).
    audit.names(session_id=sid)

    # STEP 3: SPEND THE CODE, recording which family it created. A lost claim
    # means a concurrent exchange won: this family is an orphan nobody holds a
    # token for, so it is discarded, and a failure to discard is tolerated --
    # the orphan holds a hash nobody has and expires within the hour. A claim
    # that RAISES discards the family the same way before the exception
    # propagates (amended 1 October 2026), so no family outlives an exchange
    # that issued nothing. Either row keeps the `session_id`, which is how a
    # lost claim's `device_code_spent` row differs from a replay's.
    #
    # A CLAIM THAT RAISES A STORE OUTAGE may or may not have committed (an
    # EXEC whose reply was lost). The family is discarded either way, then the
    # code is re-read: only a code PROVABLY unspent gets a retryable 503. A
    # spent code, a gone one or a re-read that fails too re-raises the claim's
    # exception, a 500: a committed claim means a spent code whose session was
    # just discarded, and the customer re-pairs (spec section 5, note of
    # 1 October 2026).
    store: DeviceCodeStoreBase = request.app.state.device_code_store
    try:
        claimed = await store.consume_device_code(code.device_code, session_id=sid)
    except DEVICE_STORE_OUTAGES as exc:
        await _discard_orphan(sessions, sid, "a claim that raised")
        try:
            reread = await store.get_device_code(code.device_code)
        except Exception as reread_exc:  # noqa: BLE001 -- unknown state, the claim's error stands
            logger.warning(
                "device grant: re-read after a failed claim failed too (%s)",
                type(reread_exc).__name__,
            )
            raise exc from reread_exc
        if reread is None or reread.exchanged_at is not None:
            raise
        logger.warning(
            "device grant: device-code store unavailable (%s) at the claim; the code is unspent",
            type(exc).__name__,
        )
        return store_unavailable_response(retry_after), type(exc).__name__
    except Exception:
        await _discard_orphan(sessions, sid, "a claim that raised")
        raise
    if not claimed:
        await _discard_orphan(sessions, sid, "a lost claim")
        return _unredeemable_response(), DETAIL_DEVICE_CODE_SPENT

    # STEP 4: SIGN. A raise leaves the code spent and a family holding a
    # never-issued `jti`; harmless, and the customer re-pairs.
    access_token = minter.sign(claims)
    return (
        JSONResponse(
            status_code=200,
            content={
                "access_token": access_token,
                "token_type": "Bearer",
                "expires_in": ACCESS_TOKEN_LIFETIME_SECONDS,
                "refresh_token": refresh_token,
                "scope": scope,
            },
        ),
        None,
    )


# ---------------------------------------------------------------------------
# Token endpoint -- POST /token with grant_type=refresh_token.
# ---------------------------------------------------------------------------


class MalformedParameter(ValueError):
    """A ``/token`` parameter that is repeated, or a file part that is not UTF-8."""


def _form_value(form: Any, name: str) -> str | None:
    """A form field as a string, ``None`` when absent. A file part is read.

    Raises `MalformedParameter` when the parameter occurs more than once
    (RFC 6749 section 3.2: "Request and response parameters MUST NOT be
    included more than once"), where ``form.get`` would silently keep the
    last value, and when a file part does not decode as UTF-8.
    """
    values = form.getlist(name)
    if not values:
        return None
    if len(values) > 1:
        raise MalformedParameter(f"{name} must not be repeated")
    raw = values[0]
    if not hasattr(raw, "file"):
        return str(raw)
    try:
        return str(raw.file.read().decode("utf-8"))
    except UnicodeDecodeError:
        raise MalformedParameter(f"{name} is not UTF-8") from None


def _unrefreshable_response() -> JSONResponse:
    """The one ``invalid_grant`` every refused refresh gets.

    RFC 6749 section 5.2's code for a grant that is "invalid, expired,
    revoked ... or was issued to another client". One body for every reason,
    for the reason `_unredeemable_response` gives: the distinction belongs in
    ``audit_log.detail``, where the caller cannot read it.
    """
    return _error(400, "invalid_grant", "refresh token cannot be redeemed")


def _log_unknown_refresh(request: Request, sid: str) -> None:
    """One warning per family per `UNKNOWN_REFRESH_LOG_INTERVAL_SECONDS`, per process.

    A presented value whose ``sid`` names a real family and whose hash the
    family never issued. It proves nothing (the ``sid`` is in every access
    token), so it writes no row; the log line is rate-limited so the same
    caller cannot flood the log instead. The ``sid`` is logged, never the
    presented value.
    """
    seen: OrderedDict[str, float] | None = getattr(request.app.state, "_unknown_refresh_log", None)
    if seen is None:
        seen = OrderedDict()
        request.app.state._unknown_refresh_log = seen
    now = time.monotonic()
    last = seen.get(sid)
    if last is not None and now - last < UNKNOWN_REFRESH_LOG_INTERVAL_SECONDS:
        return
    seen.pop(sid, None)
    seen[sid] = now
    while len(seen) > UNKNOWN_REFRESH_LOG_ENTRIES:
        seen.popitem(last=False)
    logger.warning(
        "refresh grant: a refresh token this family never issued was presented for family %s",
        sid,
    )


async def _reassert(store: RevocationStoreBase, jtis: tuple[str, ...]) -> None:
    """Put every live access token of a revoked family on the ZT-7 list.

    An idempotent set add per ``jti``. Re-running it on every presentation of
    a revoked family is what makes a failed write at reuse or recall converge.
    """
    for jti in jtis:
        await store.revoke_session(jti=jti)


async def _refresh_grant(
    request: Request, form: Any, *, at: datetime, started: float
) -> JSONResponse:
    """``grant_type=refresh_token``, spec section 6 steps 1 to 3 and the row.

    The shape checks and the lookup write nothing. From the proof of
    possession on -- the presented token's hash is the family's current one
    or a retained one -- every exit writes exactly one row, through
    ``PairingAudit`` with ``REFRESH_TOOL_NAME``, naming the family's customer
    and ``session_id``.
    """
    settings: ConfirmSettings = request.app.state.settings
    try:
        presented = _form_value(form, "refresh_token")
        client_id = _form_value(form, "client_id")
        requested_scope = _form_value(form, "scope")
    except MalformedParameter as exc:
        return _error(400, "invalid_request", str(exc))
    if not presented:
        return _error(400, "invalid_request", "refresh_token is required")
    unserved = _resource_refusal(form, settings)
    if unserved is not None:
        return unserved
    sid = sid_of(presented)
    if sid is None:
        return _unrefreshable_response()
    sessions: RefreshSessionStoreBase = request.app.state.refresh_session_store
    try:
        family = await sessions.get(sid)
    except SESSION_STORE_OUTAGES as exc:
        # NO ROW: nothing is proven yet. Retryable, with the 503s' header.
        logger.warning(
            "refresh grant: refresh-family store unavailable (%s); refusing to look up",
            type(exc).__name__,
        )
        return store_unavailable_response(settings.device_poll_interval_seconds)
    if family is None:
        return _unrefreshable_response()

    # STEP 3: PROOF OF POSSESSION BEFORE ANYTHING IS RECORDED.
    presented_hash = hash_refresh_token(presented)
    retained = presented_hash in family.retained_hashes
    if not retained and not hmac.compare_digest(family.current_hash, presented_hash):
        _log_unknown_refresh(request, sid)
        return _unrefreshable_response()

    db: Database = request.app.state.postern_database
    audit = PairingAudit(
        db=db,
        call_id=str(uuid.uuid4()),
        at=at,
        started=started,
        subject=family.customer_ref,
        claims={},
        client_ip_value=pairing_client_ip(request, settings.trusted_proxy_hops),
        tool_name=REFRESH_TOOL_NAME,
        route=TOKEN_ROUTE,
    )
    audit.names(session_id=sid, paired_client_id=family.client_id)
    try:
        response, detail = await _refresh(
            request,
            client_id=client_id,
            requested_scope=requested_scope,
            family=family,
            presented_hash=presented_hash,
            retained=retained,
        )
    except Exception as exc:
        try:
            await audit.refused(type(exc).__name__)
        except Exception as audit_exc:
            logger.error(
                "audit write failed for a session refresh after it raised %s: %s",
                type(exc).__name__,
                describe_exception(audit_exc),
                exc_info=exc_info_for_log(audit_exc),
            )
            raise exc from audit_exc
        raise
    # COMMITTED BEFORE THE RESPONSE, for the reason `_token_response` gives.
    try:
        if detail is None:
            await audit.minted()
        else:
            await audit.refused(detail)
    except Exception as audit_exc:
        logger.error(
            "audit write failed for a session refresh that answered %d; failing the request: %s",
            response.status_code,
            describe_exception(audit_exc),
            exc_info=exc_info_for_log(audit_exc),
        )
        raise
    return response


async def _refresh(
    request: Request,
    *,
    client_id: str | None,
    requested_scope: str | None,
    family: RefreshSession,
    presented_hash: str,
    retained: bool,
) -> tuple[JSONResponse, str | None]:
    """Spec section 6 steps 4 to 9, returning ``(response, detail)``.

    ``detail`` is ``None`` only for a rotation that issued a session. The
    ZT-7 checks run before the rotation spends anything, the ordering
    ``_exchange`` argues for its claim.
    """
    sessions: RefreshSessionStoreBase = request.app.state.refresh_session_store
    revocations = revocation_store(request)
    # Every retryable 503 below carries ``Retry-After``, the poll interval
    # ``/token`` uses for its device-code 503s (spec, Discrepancies 5).
    settings: ConfirmSettings = request.app.state.settings
    retry_after = settings.device_poll_interval_seconds
    now = datetime.now(UTC)

    # STEP 4: CLASSIFY.
    if family.revoked_at is not None:
        return await _answer_revoked(revocations, family, now, retry_after)
    if retained:
        return await _answer_reuse(sessions, revocations, family, retry_after)
    if family.generation >= MAX_GENERATIONS:
        return _unrefreshable_response(), DETAIL_SESSION_GENERATIONS_EXHAUSTED
    if family.is_expired(now):
        return _unrefreshable_response(), DETAIL_SESSION_EXPIRED
    if client_id is not None and client_id != family.client_id:
        return _unrefreshable_response(), DETAIL_CLIENT_ID_MISMATCH

    # STEP 5: SCOPE. Absent or empty after canonicalization is "the scope
    # originally granted" (RFC 6749 section 6); wider is refused.
    requested = canonical_scope(requested_scope or "")
    granted = family.scopes
    if requested:
        if not set(requested.split(" ")) <= set(family.scopes.split(" ")):
            return (
                _error(400, "invalid_scope", "the requested scope exceeds the grant"),
                DETAIL_SCOPE_EXCEEDED,
            )
        granted = requested

    # STEP 6: ZT-7, BEFORE THE ROTATION SPENDS ANYTHING.
    try:
        refused = await _refresh_revoked(revocations, family, now)
        stamp = await revocations.customer_revoked_at(family.customer_ref)
        client_stamp = await revocations.client_revoked_at(family.client_id)
    except RevocationStoreUnavailable as exc:
        logger.warning("refresh grant: revocation store unavailable, refusing to rotate")
        return store_unavailable_response(retry_after), type(exc).__name__
    if refused:
        log_refusal("a session refresh")
        return _unrefreshable_response(), DETAIL_REVOKED
    if any(s is not None and s >= family.created_ms for s in (stamp, client_stamp)):
        # ISSUED BEFORE A CUSTOMER REVOCATION OR A KILL SWITCH (the latter
        # since 3 October 2026): refused, and the family is revoked for good,
        # so no later restore can revive it. Reached only once the revocation
        # is restored; while it stands the check above refuses without
        # revoking. Its live access tokens go on the ZT-7 list now, not at the
        # client's next refresh: the api would otherwise honour them for up to
        # their remaining lifetime.
        log_refusal("a session refresh of a family issued before a revocation")
        outage: str | None = None
        try:
            jtis = await sessions.revoke(family.sid, reason="issued_before_revocation")
        except SESSION_STORE_OUTAGES as exc:
            # Still refused: the stamp refuses this family on every
            # presentation for the rest of its life, which the stamp's TTL
            # covers, so the outage costs only the revocation's permanence.
            # The live access tokens are cut from the record this request
            # read, so they die now either way.
            logger.warning(
                "refresh grant: could not revoke family %s issued before a revocation: %s",
                family.sid,
                type(exc).__name__,
            )
            outage = type(exc).__name__
            jtis = family.live_jtis(now)
        try:
            await _reassert(revocations, jtis or ())
        except RevocationStoreUnavailable as exc:
            # Retryable: a revoked family re-asserts on its next presentation,
            # and an unrevoked one meets this branch again.
            return store_unavailable_response(retry_after), type(exc).__name__
        return _unrefreshable_response(), outage or DETAIL_ISSUED_BEFORE_REVOCATION

    # STEP 7: DRAW.
    minter: SessionTokenMinter = request.app.state.session_minter
    new_token = new_refresh_token(family.sid)
    claims = minter.prepare(
        customer=CustomerRef(value=family.customer_ref),
        client_id=family.client_id,
        scope=granted,
        sid=family.sid,
    )

    # STEP 8: ROTATE, one compare-and-set. Any result but ROTATED re-runs the
    # matching branch of step 4 against what the transaction saw: a
    # concurrent refresh that won turns this one into REUSED.
    #
    # A STORE OUTAGE is a retryable 503 that issued nothing. If the store
    # committed the rotation before the reply was lost, the client's retry
    # with the same token is reuse and revokes the family: the customer
    # re-pairs. Accepted (spec section 6, note of 1 October 2026).
    try:
        outcome = await sessions.rotate(
            family.sid,
            presented_hash=presented_hash,
            new_hash=hash_refresh_token(new_token),
            access_jti=claims.jti,
            access_expires_at=datetime.fromtimestamp(claims.exp, UTC),
        )
    except SESSION_STORE_OUTAGES as exc:
        logger.warning(
            "refresh grant: refresh-family store unavailable (%s); refusing to rotate",
            type(exc).__name__,
        )
        return store_unavailable_response(retry_after), type(exc).__name__
    if outcome.rotation is Rotation.REUSED:
        return await _reuse_detected(revocations, family, outcome.jtis, retry_after)
    if outcome.rotation is Rotation.REVOKED:
        try:
            await _reassert(revocations, outcome.jtis)
        except RevocationStoreUnavailable as exc:
            return store_unavailable_response(retry_after), type(exc).__name__
        return _unrefreshable_response(), DETAIL_SESSION_REVOKED
    if outcome.rotation is Rotation.EXHAUSTED:
        return _unrefreshable_response(), DETAIL_SESSION_GENERATIONS_EXHAUSTED
    if outcome.rotation is Rotation.GONE:
        return _unrefreshable_response(), DETAIL_SESSION_EXPIRED
    if outcome.rotation is not Rotation.ROTATED:
        # UNKNOWN after step 3's proof means the record was replaced under a
        # presentation it had accepted. Fail closed and loudly: the row
        # records the exception's type.
        raise RuntimeError(f"family {family.sid} no longer holds a hash it held a moment ago")

    # STEP 9: SIGN. A raise leaves the family rotated and the client's token
    # retained; its retry is reuse and revokes the family. Fail closed.
    access_token = minter.sign(claims)
    return (
        JSONResponse(
            status_code=200,
            content={
                "access_token": access_token,
                "token_type": "Bearer",
                "expires_in": ACCESS_TOKEN_LIFETIME_SECONDS,
                "refresh_token": new_token,
                "scope": granted,
            },
        ),
        None,
    )


async def _refresh_revoked(
    revocations: RevocationStoreBase, family: RefreshSession, now: datetime
) -> bool:
    """The first two ZT-7 checks of spec section 6 step 6.

    The customer under any client, as ``/token`` asks; then the pair and the
    kill switch, once on their own and once beside each live access ``jti``,
    so an operator who revokes a live access token's ``jti`` also stops the
    family refreshing past it. The check without a ``jti`` is there for a
    family whose access tokens have all expired, which would otherwise ask
    the pair and the kill switch nothing.
    """
    if await revocations.is_customer_revoked(family.customer_ref):
        return True
    base = {"sub": family.customer_ref, "client_id": family.client_id}
    if await revocations.is_revoked(base):
        return True
    for jti in family.live_jtis(now):
        if await revocations.is_revoked({**base, "jti": jti}):
            return True
    return False


async def _answer_revoked(
    revocations: RevocationStoreBase, family: RefreshSession, now: datetime, retry_after: int
) -> tuple[JSONResponse, str | None]:
    """A revoked family: re-assert its live jtis on the ZT-7 list, then refuse."""
    try:
        await _reassert(revocations, family.live_jtis(now))
    except RevocationStoreUnavailable as exc:
        return store_unavailable_response(retry_after), type(exc).__name__
    return _unrefreshable_response(), DETAIL_SESSION_REVOKED


async def _answer_reuse(
    sessions: RefreshSessionStoreBase,
    revocations: RevocationStoreBase,
    family: RefreshSession,
    retry_after: int,
) -> tuple[JSONResponse, str | None]:
    """A retained token on a live family: revoke it, then list its jtis.

    A store outage (`SESSION_STORE_OUTAGES`) answers 503 under its type
    name and leaves the family unrevoked, so the retained token is reuse
    again on its next presentation; any other exception is a fault and
    propagates.
    """
    try:
        jtis = await sessions.revoke(family.sid, reason="reuse")
    except SESSION_STORE_OUTAGES as exc:
        return store_unavailable_response(retry_after), type(exc).__name__
    return await _reuse_detected(revocations, family, jtis or (), retry_after)


async def _reuse_detected(
    revocations: RevocationStoreBase,
    family: RefreshSession,
    jtis: tuple[str, ...],
    retry_after: int,
) -> tuple[JSONResponse, str | None]:
    logger.warning(
        "refresh grant: a retained refresh token was presented; family %s (device code %s) "
        "is revoked",
        family.sid,
        family.device_code_handle,
    )
    try:
        await _reassert(revocations, jtis)
    except RevocationStoreUnavailable as exc:
        return store_unavailable_response(retry_after), type(exc).__name__
    return _unrefreshable_response(), DETAIL_REFRESH_REUSED


async def _discard_orphan(sessions: RefreshSessionStoreBase, sid: str, after: str) -> None:
    """Discard a family no token was issued for, tolerating a failure.

    The orphan holds a hash nobody has and expires within the hour, so a
    failed discard is logged with the ``sid`` and never replaces the answer.
    """
    try:
        await sessions.discard(sid)
    except Exception as exc:  # noqa: BLE001 -- an orphan is harmless, the claim is not
        logger.warning(
            "device grant: could not discard orphaned session family %s after %s: %s",
            sid,
            after,
            type(exc).__name__,
        )


def _session_store_unavailable_response(retry_after: int) -> JSONResponse:
    """The 503 ``POST /token`` answers when no family can be created.

    The store is full, or it could not answer (amended 1 October 2026; this
    was ``_session_store_full_response``). One body for both: the browser's
    remedy is the same, and the row's ``detail`` (the exception's class name)
    is where an operator tells them apart. The shape of
    `_store_full_response`, with ``Retry-After`` set to the poll interval
    rather than the device-code lifetime: the code is live, paced, and
    redeemable the moment a family can be created.
    """
    return JSONResponse(
        status_code=503,
        content={
            "error": "temporarily_unavailable",
            "error_description": "the service cannot open a new session right now; retry shortly",
        },
        headers={"Retry-After": str(retry_after)},
    )


# ---------------------------------------------------------------------------
# Approval callback — POST /approve.
#
# Called by the operator's banking app after the user has scanned the QR
# (``POST /scan``), compared the pairing codes and completed identity
# verification. It marks the device code approved so the browser's poll at
# ``POST /token`` stops answering ``authorization_pending`` and is issued a
# session instead.
#
# The app sends ``user_code`` and nothing else that names the pairing.
# ``device_code`` is refused if present: it is the only credential
# ``POST /token`` asks for, it is never in the QR, and the app never learns
# it, so a body carrying one is an app on the old contract and must fail
# loudly rather than be half-honoured.
#
# It does NOT send the customer. That is audit finding C-01: the handler used
# to read `subject_value` from this body, write it onto the device code, and
# `/token` then minted from it, with a comment claiming the value came "from
# the app's authenticated session" while nothing authenticated at all. The
# customer now comes from the `sub` of the verified bearer assertion and from
# nowhere else. There is deliberately no body field a caller could use to
# influence it, so there is nothing here to forget to ignore.


def _normalize_user_code(raw: str) -> str:
    """Fold a pairing code to the stored form.

    Stored codes are six characters drawn from
    ``23456789ABCDEFGHJKLMNPQRSTUVWXYZ``; both surfaces show them as
    ``XXX-XXX`` (``DeviceCode.user_code_display``). RFC 8628 §6.1 asks a
    server to accept the code the way a human would type or paste it, so the
    separator and surrounding whitespace come out and the case is folded up.

    Nothing else is stripped. Being liberal here would widen what counts as a
    match, and this value is a credential.
    """
    return raw.strip().replace("-", "").replace(" ", "").upper()


#: The length of a stored pairing code. A presented value that normalises to
#: any other length cannot name a pairing, so it is answered as a lookup miss
#: without a store round trip -- which also keeps a 64 KiB body from becoming
#: a 64 KiB Redis key.
_USER_CODE_LENGTH = 6


async def _lookup_by_user_code(store: DeviceCodeStoreBase, presented: str) -> DeviceCode | None:
    """The live pairing a presented ``user_code`` names, or ``None``."""
    normalized = _normalize_user_code(presented)
    if len(normalized) != _USER_CODE_LENGTH:
        return None
    return await store.get_by_user_code(normalized)


def _unpairable_response() -> JSONResponse:
    """The one 400 both app routes answer for every refusal that could leak
    whether a pairing exists.

    ``POST /scan`` gives it for an unknown or expired code, an approved one,
    and a malformed or forged rotation token; ``POST /approve`` for an
    unknown or expired code, one nobody scanned, one another customer
    scanned, and one already approved for somebody else. Byte for byte the
    same, for the reason
    ``_unredeemable_response`` gives at ``POST /token``: the distinction the
    caller does not get is exactly the one an operator needs, so it lives in
    ``audit_log.detail`` and nowhere a caller can read it.

    ``invalid_grant`` is RFC 6749 section 5.2's code for a grant that is
    "invalid, expired, revoked", which is true of every case above.
    """
    return _error(400, "invalid_grant", "this pairing cannot be completed")


def _approved_response() -> JSONResponse:
    """``POST /approve``'s one success body, for the approval and its repeat.

    One function so the approver's retry cannot drift from the first answer:
    the app is told the same thing both times because the same thing is true.
    """
    return JSONResponse(status_code=200, content={"status": "approved"})


@dataclasses.dataclass(frozen=True, slots=True)
class _Pairing:
    """What ``_pair`` decided, and what the caller owes ``audit_log`` for it.

    A record rather than a tuple because three of its four fields are empty
    on most exits and a positional ``(response, None, True, None)`` at eight
    return sites is unreadable. Each field is what one exit has to say.
    """

    #: What the caller is told. The status code and ``detail`` below are
    #: deliberately independent: two exits answer 400 with the same body for
    #: different reasons, which is an absent oracle in the RESPONSE and would
    #: be a lost signal in the TABLE.
    response: JSONResponse
    #: The ``DETAIL_*`` literal for a refusal that concluded something about
    #: a customer or a device code. ``None`` on the exit that granted the
    #: pairing and on the approver's repeat, which ``repeated`` names instead.
    detail: str | None = None
    #: Whether this exit owes a row at all. ``False`` is the other half of
    #: ``PairingAudit``'s rule: a malformed request is answered by looking at
    #: the request and consulting nothing, so it concluded nothing to record.
    recorded: bool = True
    #: The device code this exit APPROVED, so the caller can withdraw the
    #: pairing if the row cannot be written. ``None`` wherever nothing was
    #: approved, which is every exit but one. ``None`` on the approver's
    #: repeat too: it approved nothing, and the approval it reports was
    #: recorded by the first request's row, so a failed second row withdraws
    #: nothing.
    approved_device_code: str | None = None
    #: The approver's repeat of an approval that stands, answered with the
    #: first one's 200 and recorded by ``PairingAudit.approved_again``.
    repeated: bool = False


async def approve_callback(request: Request) -> JSONResponse:
    """Banking app approval callback for a device pairing, and its audit row.

    Requires a verified app assertion (``services/confirm/auth.py``). The
    customer is the assertion's ``sub``.

    Request body:
        user_code: The pairing code the app read from the scanned QR,
            ``XXX-XXX`` or bare. A body that also carries ``device_code`` is
            refused.

    Response (200): ``{"status": "approved"}``, for the approval and, since
        2026-09-30, for the approving customer's repeat of it while it is
        unexpired (see ``_answer_refused_approval``).
    Response (400): ``invalid_request`` for a malformed body or one still
        carrying ``device_code``, and the one ``invalid_grant`` body of
        ``_unpairable_response`` for every refusal that concerns a pairing.
    Response (401): no verified assertion.
    Response (403): the assertion verified but its ``sub`` is not a customer
        reference (``invalid_subject``), or that customer's access has been
        revoked (``access_revoked``, ZT-7).

    WHAT IS RECORDED, AND WHAT WAS NOT UNTIL 2026-09-26. This handler wrote no
    ``audit_log`` row on any branch. The pairing that authorises an AI client
    to exist against a customer's data left no trace at all, while the payment
    approvals that pairing makes possible left two rows each -- so an operator
    investigating a rogue client could see what it did and never see who let
    it in. ``services/confirm/audit.py``'s ``PairingAudit`` owns every
    decision about the row: one row rather than the read path's two, which
    refusals earn one, what the row carries in place of the device code
    itself, and why a pairing that cannot be audited is withdrawn rather than
    merely reported as failed.

    WHAT THIS FUNCTION OWNS is the two instants at the top, the correlation
    id, and the mapping from each exit to an outcome -- the same division
    ``services/confirm/callback.py`` draws with the same module. Both instants
    are read as the first statements, so everything below is inside the
    measurement and the only thing outside it is ``AppAssertionMiddleware``.
    """
    # FIRST TWO STATEMENTS. `at` is a wall clock because every instant on
    # this table has to be comparable with the others; `started` is monotonic
    # because it measures an interval and a clock that steps backwards under
    # an NTP correction would write a negative duration into an append-only
    # table.
    at = datetime.now(UTC)
    started = time.monotonic()

    subject = verified_subject(request)
    if subject is None:
        # Unreachable through the assembled app: `AppAssertionMiddleware`
        # already refused. Reachable if a future route table forgets to wire
        # it, which is how this control would silently stop applying.
        #
        # NO ROW. There is no customer here for a row to be about, and the
        # middleware's own refusal is already logged. Same backstop, same
        # reasoning, as `services/confirm/callback.py`'s first exit.
        return unauthenticated_response()

    settings: ConfirmSettings = request.app.state.settings
    # Typed rather than left as the `Any` that `app.state` hands back, so
    # `PairingAudit` is checked against the real sessionmaker.
    db: Database = request.app.state.postern_database
    store: DeviceCodeStoreBase = request.app.state.device_code_store

    audit = PairingAudit(
        db=db,
        call_id=str(uuid.uuid4()),
        at=at,
        started=started,
        subject=subject,
        claims=verified_claims(request),
        client_ip_value=pairing_client_ip(request, settings.trusted_proxy_hops),
    )

    try:
        outcome = await _pair(request, audit, store=store, subject=subject)
    except Exception as exc:
        # `raise exc from audit_exc`, never a bare `raise` from inside this
        # handler: an audit-write failure must not REPLACE the exception that
        # ended the request, or the operator reading the traceback learns
        # what the database did and not what the pairing did. Same shape as
        # `services/confirm/callback.py`'s raised branch.
        #
        # A RAISE MAY FOLLOW A COMMITTED APPROVAL. The only write in `_pair`
        # is `approve_scanned`, and on Redis its `pipe.execute()` can raise a
        # timeout or a connection error after the server ran `EXEC`, leaving
        # the code approved behind a row that says refused. `_pair` therefore
        # withdraws the pairing before that exception reaches this branch, so
        # the ambiguous case fails closed and the customer re-pairs. Nothing
        # after a successful `approve_scanned` can raise, and nothing before
        # it wrote anything, so there is nothing left to withdraw here.
        try:
            await audit.refused(type(exc).__name__)
        except Exception as audit_exc:
            logger.error(
                "audit write failed for a device pairing after it raised %s: %s",
                type(exc).__name__,
                describe_exception(audit_exc),
                exc_info=exc_info_for_log(audit_exc),
            )
            raise exc from audit_exc
        raise

    if not outcome.recorded:
        return outcome.response

    try:
        if outcome.repeated:
            await audit.approved_again()
        elif outcome.detail is None:
            await audit.approved()
        else:
            await audit.refused(outcome.detail)
    except Exception as audit_exc:
        # FAIL CLOSED, AND HERE THAT MEANS UNDOING THE PAIRING. One endpoint
        # over the same failure can only be reported, because the money has
        # already moved and this process cannot unmove it. A pairing is in
        # this deployment's own store, so leaving it standing behind a 500
        # would be fail-closed in the response and fail-open in substance:
        # the browser polls `/token` against an approval no row names and is
        # handed a session for it.
        # `PairingAudit` carries the full argument and what the availability
        # cost is.
        if outcome.approved_device_code is not None:
            await _withdraw_pairing(
                store, outcome.approved_device_code, cause="audit", state="approved"
            )
        logger.error(
            "audit write failed for a device pairing that answered %d; "
            "failing the request because the pairing could not be recorded: %s",
            outcome.response.status_code,
            describe_exception(audit_exc),
            exc_info=exc_info_for_log(audit_exc),
        )
        raise
    return outcome.response


async def _withdraw_pairing(
    store: DeviceCodeStoreBase,
    device_code_value: str,
    *,
    cause: Literal["audit", "store", "cancelled"],
    state: Literal["approved", "claimed"],
) -> None:
    """Undo a pairing whose audit row could not be written, or whose approval
    or scan claim may have committed behind a store error.

    Revocation rather than an in-place undo, because the recovery the
    customer needs is a fresh QR anyway, and a fresh QR is what re-anchors the
    human pairing-code comparison that is the real A2 control. Rewriting
    ``approved`` or ``scanned_by`` back would leave the same ``device_code``
    live, and a racing poll or a racing scan could still find it in the state
    the failed request could not record.

    ``cause`` and ``state`` say which of the six callers this is, because
    the ERROR line below states what is left behind and each leaves a
    different thing. ``state`` names the write: ``"approved"`` on
    ``POST /approve``, ``"claimed"`` on ``POST /scan``. ``cause`` names the
    failure:

    - ``approve_callback``, ``cause="audit"``: an approval whose row could
      not be written. The code IS approved and NO row names it.
    - ``_pair``, ``cause="store"``: ``approve_scanned`` raised. The code MAY
      be approved, and a row recording the store's exception as a refusal
      will follow.
    - ``scan_callback``, ``cause="audit"``: a claim whose row could not be
      written. The code IS claimed and NO row names it.
    - ``_scan``, ``cause="store"``: ``claim_scan`` raised. The code MAY be
      claimed, and a row recording the store's exception as a refusal will
      follow.
    - ``_scan``, ``cause="cancelled"``: the request was cancelled while the
      pairing network enrichment was awaited after a ``CLAIMED`` result. The
      code IS claimed and NO row names it.
    - ``scan_callback``, ``cause="cancelled"``: the request was cancelled
      while a ``CLAIMED`` scan's row was being written. The code IS claimed,
      and the row may or may not have committed.

    ITS OWN FAILURE IS SWALLOWED, deliberately and exactly once. The caller is
    already unwinding a failure and owes the operator THAT exception;
    replacing it with the revocation's would report the second problem and
    hide the first. What is left behind in that case is the shape this
    control cannot close, so it gets an ERROR line of its own naming the
    code's handle, which is the same handle the row carries or would have
    carried.
    """
    try:
        await store.revoke_device_code(device_code_value)
    except Exception as revoke_exc:
        if cause == "audit":
            logger.error(
                "a device pairing could not be audited AND could not be withdrawn; "
                "device code %s is %s with no audit_log row behind it: %s",
                device_code_handle(device_code_value),
                state,
                describe_exception(revoke_exc),
                exc_info=exc_info_for_log(revoke_exc),
            )
        elif cause == "cancelled":
            logger.error(
                "a device pairing's scan claim was cancelled before its audit_log row "
                "was confirmed, could not be withdrawn, and device code %s may be %s "
                "with no audit_log row behind it (the request was cancelled): %s",
                device_code_handle(device_code_value),
                state,
                describe_exception(revoke_exc),
                exc_info=exc_info_for_log(revoke_exc),
            )
        else:
            logger.error(
                "a device pairing's store write failed ambiguously AND it could not be "
                "withdrawn; device code %s may be %s while its audit_log row "
                "records a refusal: %s",
                device_code_handle(device_code_value),
                state,
                describe_exception(revoke_exc),
                exc_info=exc_info_for_log(revoke_exc),
            )


async def _pair(
    request: Request,
    audit: PairingAudit,
    *,
    store: DeviceCodeStoreBase,
    subject: str,
) -> _Pairing:
    """The pairing itself, returning what the caller owes the audit log.

    Split out from ``approve_callback`` so every exit names its own outcome
    once, where the decision is made, and the row is written in exactly one
    place rather than at each return where a new exit could forget to join.
    The same division ``services/confirm/callback.py``'s ``_approve`` makes,
    for the same reason.

    THE APPROVAL IS A COMPARE-AND-SET. Until 2026-09-30 this read the code,
    checked ``approved``, and wrote the whole snapshot back with a plain
    ``SETEX``, so two replicas could both pass the check and the last writer's
    ``customer_ref`` won. ``approve_scanned`` settles it inside the store: it
    approves only a code that is unexpired, unapproved and scanned by this
    same customer, and answers ``True`` to one caller. What this function
    reads after a refusal writes nothing and approves nothing: it labels the
    audit row, and since 2026-09-30 it also picks the approver's repeat out
    of the refusals and answers it with the success body
    (``_answer_refused_approval``).
    """
    try:
        customer = CustomerRef(value=subject)
    except ValidationError:
        # The assertion is genuine but its subject is not the opaque
        # `cust_...` reference handoff §7.2 requires. That is the operator's
        # app backend minting the wrong claim, not an attacker, and it is
        # worth a distinct status. The raw value is never echoed or logged:
        # see the matching note in `token_endpoint`.
        #
        # RECORDED, with `customer_ref` NULL and the class of absence in
        # `customer_ref_absence_reason`. `postern_core.identity` warns that a
        # compromised issuer can mint a PAN-, IBAN- or DNI-shaped `sub`, and
        # this is the one row shape that says so.
        logger.warning("device approve: assertion subject is not a customer reference")
        return _Pairing(
            _error(403, "invalid_subject", "assertion subject is not a customer reference"),
            DETAIL_INVALID_SUBJECT,
        )

    # ZT-7, and placed here rather than left to ``/token`` to catch it. This
    # is the earliest point at which a verified customer exists, and refusing
    # now means ``customer_ref`` is never written onto the device code at all
    # -- strictly better than refusing the mint that would read it back,
    # because the pairing leaves no half-authorized state behind.
    #
    # `RevocationStoreUnavailable` propagates: this endpoint is
    # assertion-authenticated, like the challenge approval, so it takes that
    # path's shape (a 500, nothing written) rather than ``/token``'s 503. The
    # party here is the operator's own app, which retries on its own terms;
    # the browser polling ``/token`` is the one that needed a retryable code.
    # It is now also recorded, by `approve_callback`'s `except Exception`,
    # under the exception's own type -- "we tried to decide and could not" is
    # a conclusion about this customer even though it names no verdict.
    #
    # THE ROW THIS PRODUCES NAMES NO DEVICE CODE, because the body has not
    # been read yet and this check must not move behind it. That is the same
    # ordering `services/confirm/callback.py` documents for its own
    # revocation check, and the same consequence: a revoked caller is counted
    # under `detail = 'revoked'` without the table saying which pairing they
    # were after.
    if await customer_revoked(request, customer.value):
        log_refusal("a device pairing approval")
        return _Pairing(
            revoked_response("this customer's access has been revoked"),
            DETAIL_REVOKED,
        )

    try:
        body = loads_finite(await request.body())
    except (ValueError, RecursionError):
        return _Pairing(_error(400, "invalid_request", "body must be JSON"), recorded=False)
    if not isinstance(body, dict):
        return _Pairing(
            _error(400, "invalid_request", "body must be a JSON object"), recorded=False
        )

    # THE OLD CONTRACT IS REFUSED, NOT IGNORED. An app still sending
    # ``device_code`` was built against a QR that carried it, and ignoring the
    # field would let that app half-work until the day it did not. A 400 it
    # cannot mistake for a pairing refusal is the loud failure.
    if "device_code" in body:
        return _Pairing(
            _error(400, "invalid_request", "device_code is not accepted; send user_code only"),
            recorded=False,
        )

    user_code_value = body.get("user_code", "")

    # `isinstance`, not just truthiness. JSON gives a caller ints, lists and
    # objects as easily as strings, and `{"user_code": 123}` would otherwise
    # reach `_normalize_user_code` and raise `AttributeError` -- a 500 from an
    # endpoint that should answer 400. On an authenticated write path a 500 is
    # also the shape that gets "fixed" by relaxing something.
    if not isinstance(user_code_value, str):
        return _Pairing(
            _error(400, "invalid_request", "user_code must be a string"), recorded=False
        )
    if not user_code_value:
        return _Pairing(_error(400, "invalid_request", "user_code is required"), recorded=False)

    # THE EXITS ABOVE ARE THE RULE'S OTHER HALF. Each is answered by looking
    # at the request and consulting nothing, each names no pairing, and a row
    # for each would hand a caller holding one valid assertion an INSERT per
    # malformed body. `PairingAudit` carries the rule and what excluding them
    # costs.

    existing = await _lookup_by_user_code(store, user_code_value)
    if existing is None:
        return _Pairing(_unpairable_response(), DETAIL_USER_CODE_NOT_FOUND)

    # From here the request names a pairing, so every exit below is a
    # conclusion about one and every exit below is recorded. WHICH CLIENT IS
    # BEING PAIRED is the other half of the name: the browser supplied it,
    # unauthenticated, at `/device_authorization`, and it is never an
    # identity, but on every refused path below it exists nowhere else once
    # the code expires.
    audit.names(device_code=existing.device_code, paired_client_id=existing.client_id)

    try:
        approved = await store.approve_scanned(existing.device_code, customer.value)
    except DeviceCodeStoreContended:
        # DEFINITELY NOT WRITTEN: every `WATCH` was beaten, so no transaction
        # committed. Withdrawing would only end a pending pairing the customer
        # can still complete, so this one propagates untouched.
        raise
    except Exception:
        # AN EXCEPTION HERE DOES NOT MEAN NOTHING WAS WRITTEN. On Redis the
        # reply to `EXEC` can be lost to a timeout or a dropped connection
        # after the server committed, so the code may be approved. Withdraw it
        # before the exception propagates: `approve_callback` records the
        # exception's type as a refusal, and a refusal row over a standing
        # approval is the fail-open shape. `_withdraw_pairing` swallows its own
        # failure, so the exception re-raised is still the store's.
        #
        # `asyncio.CancelledError` is a `BaseException` and is NOT caught here:
        # a client disconnecting mid-`execute()` cancels the task and skips the
        # withdrawal. That is the same residual class as the hard process kill
        # `PairingAudit` already names -- the process stops running this code
        # at an arbitrary point -- and it is accepted on the same terms.
        await _withdraw_pairing(store, existing.device_code, cause="store", state="approved")
        raise

    if approved:
        # THE STORE WRITE COMES FIRST AND THE ROW FOLLOWS, which is the
        # opposite of the read path's entry row and is chosen for a measurable
        # reason rather than by analogy. Writing the row first would make every
        # failure of the line above -- a Redis timeout, a failover, an ordinary
        # blip on the backend `POSTERN_REDIS_URL` names -- produce a durable
        # row saying a pairing succeeded when none did. This order instead
        # makes "no row" mean "no pairing" on every path but one: a hard
        # process kill between this line and the INSERT, which `PairingAudit`
        # names as the residual.
        return _Pairing(_approved_response(), approved_device_code=existing.device_code)

    return await _answer_refused_approval(store, existing.device_code, customer.value)


async def _answer_refused_approval(
    store: DeviceCodeStoreBase, device_code_value: str, customer_ref: str
) -> _Pairing:
    """What a refused ``approve_scanned`` answers, and under which ``detail``.

    Read from the row AFTER the compare-and-set refused, in the order
    ``dev-docs/qr-page-spec.md`` section 6 fixes: gone or expired by now,
    then nobody scanned it, then somebody else did, then it is already
    approved. The read writes nothing -- the refusal has happened -- so the
    race between the two reads can only move a row from one answer to
    another, never approve anything.

    ONE EXIT ANSWERS 200, SINCE 2026-09-30: a row that is approved, unexpired,
    scanned by this customer and approved FOR this customer. That is the
    approver retrying, normally because the first 200 was lost, and until
    then the retry got the one ``invalid_grant`` body, so the app could not
    tell "your approval stands" from "refused". It now gets the first
    request's body back, ``PairingAudit.approved_again`` records it, and the
    store is not written. Nothing leaks: only the customer who scanned and
    approved the code can reach this answer, and they know the pairing
    exists. Every other refusal keeps the identical 400.

    The race runs the harmless way here. A same-customer approval that
    commits between the refused compare-and-set and this read is an approval
    that stands, and reporting it as one is true.

    THE ONE RESIDUAL: this read can land just before a concurrent withdrawal
    or conflict recall deletes the row, and the repeat then answers 200 and
    writes ``returned`` with ``already_approved`` for a pairing that no
    longer stands. The window is two store round trips wide and it grants
    nothing: nothing is written to the store, and ``POST /token`` issues
    nothing for a revoked code.

    A ROW THAT PASSES ALL FOUR is scanned by this customer, unexpired and
    unapproved, which is what ``approve_scanned`` approves -- so at the moment
    it refused, the row was NOT scanned by this customer. On Redis the refusal
    and this read are two round trips, and the same customer's ``POST /scan``
    can commit between them. That shape is recorded as ``DETAIL_NOT_SCANNED``,
    the state the compare-and-set saw, and answered with the same
    ``invalid_grant`` as every other refusal. Raising here would turn a race
    the caller can trigger into a 500, which is a second response shape and
    so an oracle.

    A RE-READ THAT RAISES is labelled ``DETAIL_NOT_SCANNED`` for the same
    reason: the refusal has happened, the label only describes it, and a
    store outage here must not turn the one ``invalid_grant`` into a 500.
    Nor into the 200: that answer is earned only by a row this read
    returned, so without one the approver's repeat stays the identical
    refusal. The exception's type goes to a WARNING instead. ``Exception``
    and not ``BaseException``, so a cancelled request still stops.
    """
    try:
        row = await store.get_device_code(device_code_value)
    except Exception as exc:
        logger.warning(
            "device approve: re-reading a refused pairing failed with %s; "
            "recording it as not_scanned",
            type(exc).__name__,
        )
        return _Pairing(_unpairable_response(), DETAIL_NOT_SCANNED)
    if row is None or row.is_expired:
        return _Pairing(_unpairable_response(), DETAIL_USER_CODE_NOT_FOUND)
    if not row.scanned_by:
        return _Pairing(_unpairable_response(), DETAIL_NOT_SCANNED)
    if row.scanned_by != customer_ref:
        return _Pairing(_unpairable_response(), DETAIL_SCANNED_BY_OTHER)
    if row.approved and row.customer_ref == customer_ref:
        return _Pairing(_approved_response(), repeated=True)
    if row.approved:
        return _Pairing(_unpairable_response(), DETAIL_ALREADY_APPROVED)
    return _Pairing(_unpairable_response(), DETAIL_NOT_SCANNED)


# ---------------------------------------------------------------------------
# Scan -- POST /scan.
#
# Called by the operator's banking app the moment it reads the QR, before the
# user has compared anything. It is the step that binds a pairing to ONE
# customer: the first customer to present a current rotation token for a
# pairing becomes its ``scanned_by``, and ``POST /approve`` approves for that
# customer and nobody else. ``dev-docs/qr-page-spec.md`` section 5 is the
# contract; the decisions below are the ones that section leaves to code.
#
# The app sends ``user_code`` and ``qr``, both read from the app link the QR
# encodes, and nothing that names a customer: that comes from the verified
# assertion's ``sub``, as on every other assertion-authenticated path.


def _qr_stale_response() -> JSONResponse:
    """A genuine rotation token that has aged out of the window.

    DISTINCT FROM ``_unpairable_response`` on purpose, and safe to be: only a
    MAC that verifies reaches it, and a caller holding one already knows the
    pairing exists. The app needs the difference to say "scan again".
    """
    return _error(400, "qr_stale", "the QR code has changed; scan the one on screen now")


def _scan_conflict_response() -> JSONResponse:
    """A second customer's scan of a pairing another customer holds.

    Distinct for the reason ``_qr_stale_response`` gives, and the app needs it
    to say "this pairing was cancelled". Reached only past a verifying MAC.
    """
    return _error(400, "scan_conflict", "this pairing was scanned by another device")


def _recall_retry_response() -> JSONResponse:
    """The 503 ``POST /scan`` answers when a recall could not complete.

    ``Retry-After: 1``, because the retry must land inside the rotation
    token's window: ``/scan`` checks the MAC before ``claim_scan``, so a retry
    later than 10 to 12 seconds answers ``qr_stale`` and recalls nothing. The
    mobile pairing contract tells the app to retry once, immediately.
    """
    return JSONResponse(
        status_code=503,
        content={
            "error": "temporarily_unavailable",
            "error_description": "the pairing could not be cancelled; retry now",
        },
        headers={"Retry-After": "1"},
    )


def _scan_context_response(code: DeviceCode) -> JSONResponse:
    """What the app shows beside the pairing code the user reads off the page.

    EVERY VALUE COMES FROM THE STORED ROW and none from the QR or the body, so
    a tampered QR cannot change what the confirmation screen says.
    ``client_id_verified`` is ``False`` on every answer because nothing on
    this path verifies it: the browser supplied ``client_id``, unauthenticated,
    at ``POST /device_authorization``, and until CIMD verification exists the
    app must not present it as an identity.
    """
    return JSONResponse(
        status_code=200,
        content={
            "client_id": code.client_id,
            "client_id_verified": False,
            "scopes": code.scopes,
            "expires_at": code.expires_at.isoformat(),
            "user_code": code.user_code_display,
        },
    )


@dataclasses.dataclass(frozen=True, slots=True)
class _Scanned:
    """What ``_scan`` decided, and what the caller owes ``audit_log`` for it.

    The shape of ``_Pairing``, one endpoint over, for the same reasons.
    """

    response: JSONResponse
    detail: str | None = None
    recorded: bool = True
    #: The device code this exit CLAIMED, so the caller can withdraw the claim
    #: if the row cannot be written. ``None`` on every other exit, including a
    #: repeat by the same customer: that claim was recorded when it was made.
    #: A ``claim_scan`` that raises never reaches this field: ``_scan``
    #: withdraws that claim itself before the exception propagates.
    claimed_device_code: str | None = None
    #: The ``detail`` of a repeat scan by the customer who already holds the
    #: pairing, answered with the first scan's 200 and recorded by
    #: ``PairingAudit.approved_again``: ``DETAIL_ALREADY_SCANNED`` before
    #: approving, ``DETAIL_ALREADY_APPROVED`` after. ``None`` on every other exit.
    repeat_detail: str | None = None
    #: The serialized ``PAIRING_NETWORK`` signal for the row, on ``CLAIMED``
    #: and ``ALREADY_MINE`` and on no other exit: ``APPROVED_MINE`` and every
    #: refusal keep ``risk_signals`` NULL.
    risk_signals: list[dict[str, Any]] | None = None


async def scan_callback(request: Request) -> JSONResponse:
    """The banking app's scan of a pairing QR, and its audit row.

    Requires a verified app assertion (``services/confirm/auth.py``); it is
    not in ``PUBLIC_PATHS``. The customer is the assertion's ``sub``.

    Request body:
        user_code: From the app link the QR encodes, ``XXX-XXX`` or bare.
        qr: The rotation token from the same link, ``<slot>.<mac>``.

    Response (200): the stored pairing's context; see ``_scan_context_response``.
        The same body, since 2026-09-30, for the approving customer's repeat
        scan of a code it already approved, with a current rotation token.
    Response (400): ``invalid_request`` for a malformed body; ``qr_stale``;
        ``scan_conflict``; and the one ``invalid_grant`` body of
        ``_unpairable_response`` for an unknown or expired code and a
        malformed, forged or future rotation token.
    Response (401): no verified assertion.
    Response (403): ``invalid_subject`` or ``access_revoked`` (ZT-7).
    Response (503): ``temporarily_unavailable`` with ``Retry-After: 1``, when
        a scan that found the pairing already exchanged could not complete
        the recall because a store was out or contended; see ``_recall``.
    Response (500): a row that could not be written, and any other raise,
        recorded under the exception's type where the row can still be written.

    ONE ROW PER RECORDED CALL, through ``PairingAudit`` with
    ``SCAN_TOOL_NAME`` and ``SCAN_ROUTE``, fail-closed per decision 0006: a
    claim whose row cannot be written is withdrawn exactly as
    ``_withdraw_pairing`` withdraws an unrecorded approval. The malformed-body
    exits write nothing, by ``PairingAudit``'s rule, as on ``POST /approve``.
    THE ONE EXCEPTION is a scan that finds the pairing already exchanged
    (``ScanClaim.CONFLICT_EXCHANGED``): ``_recall`` writes a recall row
    first, naming the recalled family's customer, and this row follows it
    with the same ``call_id``, so that call writes two rows.
    """
    at = datetime.now(UTC)
    started = time.monotonic()

    subject = verified_subject(request)
    if subject is None:
        # Unreachable through the assembled app, and no row: the backstop
        # `approve_callback` keeps, for the reason it gives.
        return unauthenticated_response()

    settings: ConfirmSettings = request.app.state.settings
    db: Database = request.app.state.postern_database
    store: DeviceCodeStoreBase = request.app.state.device_code_store

    # COMPUTED ONCE, and handed both to the row and to the claim. Two reads
    # could disagree if they ever diverged, and then the address the row
    # records would not be the address the pairing was claimed from.
    scanner_ip = pairing_client_ip(request, settings.trusted_proxy_hops)
    audit = PairingAudit(
        db=db,
        call_id=str(uuid.uuid4()),
        at=at,
        started=started,
        subject=subject,
        claims=verified_claims(request),
        client_ip_value=scanner_ip,
        tool_name=SCAN_TOOL_NAME,
        route=SCAN_ROUTE,
    )

    try:
        outcome = await _scan(request, audit, store=store, subject=subject, scanner_ip=scanner_ip)
    except Exception as exc:
        # The shape `approve_callback` uses: an audit-write failure must not
        # replace the exception that ended the request.
        #
        # A RAISE MAY FOLLOW A COMMITTED CLAIM. On Redis `claim_scan`'s
        # `pipe.execute()` can raise after the server ran `EXEC`, so `_scan`
        # withdraws the pairing before that exception reaches this branch,
        # exactly as `_pair` does for `approve_scanned`. Nothing after a
        # `CLAIMED` claim can raise. A raise after a `CONFLICT_EXCHANGED`
        # claim comes from `_recall`, which claimed nothing: what it may
        # leave behind is a revoked family or listed tokens, and that recall
        # is safe to keep. So there is nothing left to withdraw here.
        try:
            await audit.refused(type(exc).__name__)
        except Exception as audit_exc:
            logger.error(
                "audit write failed for a device pairing scan after it raised %s: %s",
                type(exc).__name__,
                describe_exception(audit_exc),
                exc_info=exc_info_for_log(audit_exc),
            )
            raise exc from audit_exc
        raise

    if not outcome.recorded:
        return outcome.response

    try:
        if outcome.repeat_detail is not None:
            await audit.approved_again(outcome.repeat_detail, risk_signals=outcome.risk_signals)
        elif outcome.detail is None:
            await audit.approved(risk_signals=outcome.risk_signals)
        else:
            await audit.refused(outcome.detail)
    except Exception as audit_exc:
        # FAIL CLOSED BY WITHDRAWING THE CLAIM, for the reason
        # `approve_callback` withdraws an approval: a claim nobody recorded
        # would still decide who may approve, and no row would say who made it.
        if outcome.claimed_device_code is not None:
            await _withdraw_pairing(
                store, outcome.claimed_device_code, cause="audit", state="claimed"
            )
        logger.error(
            "audit write failed for a device pairing scan that answered %d; "
            "failing the request because the scan could not be recorded: %s",
            outcome.response.status_code,
            describe_exception(audit_exc),
            exc_info=exc_info_for_log(audit_exc),
        )
        raise
    except BaseException:
        # A CANCELLATION DURING THE ROW WRITE is not an `Exception`, so the
        # branch above would not see it and a committed claim would stand
        # with no row naming it. Withdraw it and re-raise, as `_scan` does
        # for one arriving during enrichment; `_withdraw_pairing` swallows
        # its own failure, so what propagates is still the cancellation. The
        # write may have committed before the cancellation landed, and then
        # a `returned` row names a withdrawn pairing: the safe direction.
        if outcome.claimed_device_code is not None:
            await _withdraw_pairing(
                store, outcome.claimed_device_code, cause="cancelled", state="claimed"
            )
        raise
    return outcome.response


async def _scan(
    request: Request,
    audit: PairingAudit,
    *,
    store: DeviceCodeStoreBase,
    subject: str,
    scanner_ip: str | None,
) -> _Scanned:
    """The scan itself, in section 5's order, returning what the row owes.

    THE MAC IS CHECKED BEFORE THE CLAIM, and that order is what keeps session
    swap detection honest. A stale token from a second customer answers
    ``qr_stale`` and revokes nothing, because only a caller inside the token
    window -- one who could have been standing at the screen -- reaches
    ``claim_scan`` at all.

    ``APPROVED_MINE`` ANSWERS 200, SINCE 2026-09-30, for the reason
    ``_answer_refused_approval`` gives on ``POST /approve``: it is the
    approver retrying, normally after a lost response, and the identical
    ``invalid_grant`` left the app unable to tell "your approval stands" from
    "refused". The body is the first scan's, built from the stored row by
    ``_scan_context_response``; ``PairingAudit.approved_again`` records it,
    so ``outcome='returned' AND detail IS NULL`` never counts it; and the
    store is not written. Only a genuine in-window rotation token reaches it,
    because the MAC check above runs first. The same residual as there: the
    row can be deleted by a concurrent withdrawal or conflict recall after
    ``claim_scan`` answered, and the repeat then answers 200 and writes
    ``returned`` with ``already_approved`` for a pairing that no longer
    stands. The window is small and it grants nothing: nothing is written to
    the store, and ``POST /token`` issues nothing for a revoked code.

    ``ALREADY_MINE``, the same customer's repeat before approving, answered
    the same 200 before this date and still does; since 2026-09-30 its row is
    ``returned`` with ``DETAIL_ALREADY_SCANNED`` instead of NULL, so the NULL
    rows count first scans only.

    ``CONFLICT_EXCHANGED`` RECALLS THE SESSION (spec section 7): the swap was
    noticed after the other customer's pairing was exchanged, so the family
    ``POST /token`` issued is revoked and its access tokens listed, before the
    ``scan_conflict`` answer. `_recall` carries the order and the failure mode.
    """
    try:
        customer = CustomerRef(value=subject)
    except ValidationError:
        # As at `POST /approve`: a genuine assertion with a non-conforming
        # `sub`, never echoed or logged, recorded as an absence.
        logger.warning("device scan: assertion subject is not a customer reference")
        return _Scanned(
            _error(403, "invalid_subject", "assertion subject is not a customer reference"),
            DETAIL_INVALID_SUBJECT,
        )

    # ZT-7 before anything is read, as at `POST /approve`, and with the same
    # consequences: `RevocationStoreUnavailable` propagates to a 500 recorded
    # under the exception's type, and the row names no pairing.
    if await customer_revoked(request, customer.value):
        log_refusal("a device pairing scan")
        return _Scanned(
            revoked_response("this customer's access has been revoked"),
            DETAIL_REVOKED,
        )

    try:
        body = loads_finite(await request.body())
    except (ValueError, RecursionError):
        return _Scanned(_error(400, "invalid_request", "body must be JSON"), recorded=False)
    if not isinstance(body, dict):
        return _Scanned(
            _error(400, "invalid_request", "body must be a JSON object"), recorded=False
        )

    user_code_value = body.get("user_code", "")
    qr_value = body.get("qr", "")
    if not isinstance(user_code_value, str) or not isinstance(qr_value, str):
        return _Scanned(
            _error(400, "invalid_request", "user_code and qr must be strings"), recorded=False
        )
    if not user_code_value or not qr_value:
        return _Scanned(
            _error(400, "invalid_request", "user_code and qr are required"), recorded=False
        )

    code = await _lookup_by_user_code(store, user_code_value)
    if code is None:
        return _Scanned(_unpairable_response(), DETAIL_USER_CODE_NOT_FOUND)

    audit.names(device_code=code.device_code, paired_client_id=code.client_id)

    verdict = verify_token(code.qr_secret, code.user_code, qr_value, slot_at(time.time()))
    if verdict is QrVerdict.INVALID:
        return _Scanned(_unpairable_response(), DETAIL_QR_INVALID)
    if verdict is QrVerdict.STALE:
        return _Scanned(_qr_stale_response(), DETAIL_QR_STALE)

    try:
        claim = await store.claim_scan(code.device_code, customer.value, scanner_ip=scanner_ip)
    except DeviceCodeStoreContended:
        # DEFINITELY NOT WRITTEN: every `WATCH` was beaten, so no transaction
        # committed. Withdrawing would only end a pending pairing the customer
        # can still scan, so this one propagates untouched.
        raise
    except Exception:
        # AN EXCEPTION HERE DOES NOT MEAN NOTHING WAS WRITTEN, for the reason
        # `_pair` gives for `approve_scanned`: the claim may have committed
        # behind a lost reply, and `scan_callback` will record a refusal over
        # it. Withdraw first; `_withdraw_pairing` swallows its own failure, so
        # the exception re-raised is still the store's. `CancelledError` is
        # not caught, on the terms `_pair` states.
        await _withdraw_pairing(store, code.device_code, cause="store", state="claimed")
        raise
    if claim is ScanClaim.CLAIMED:
        # `code` is the row read before the claim, and that is the right one
        # to read `creator_ip` from: it is written once, at creation.
        #
        # A CANCELLATION HERE WITHDRAWS THE CLAIM AND RE-RAISES. A
        # `CancelledError` from a client disconnect or a shutdown, arriving
        # while the enricher is awaited, is not an `Exception`, so
        # `scan_callback`'s branch would not see it and a committed claim
        # would stand with no row at all: the fail-open shape `PairingAudit`
        # rejects. This handler sits OUTSIDE the enrichment step and
        # `asyncio.timeout` sits inside it, so the budget's own cancellation
        # has already become an "unknown" result by the time anything reaches
        # here, and a slow provider never withdraws a legitimate claim.
        # `_withdraw_pairing` swallows its own failure, so what propagates is
        # still the cancellation; a second cancellation during the withdrawal
        # is the residual `_pair` accepts around `approve_scanned`.
        try:
            signals = await _pairing_network_signals(request, code.creator_ip, scanner_ip)
        except BaseException:
            await _withdraw_pairing(store, code.device_code, cause="cancelled", state="claimed")
            raise
        return _Scanned(
            _scan_context_response(code),
            claimed_device_code=code.device_code,
            risk_signals=signals,
        )
    if claim is ScanClaim.ALREADY_MINE:
        # THIS request's address, not the stored `scanner_ip`, so the row
        # describes the request it records: the `client_ip` beside it in
        # `arguments` is the address the relation was computed from.
        signals = await _pairing_network_signals(request, code.creator_ip, scanner_ip)
        return _Scanned(
            _scan_context_response(code),
            repeat_detail=DETAIL_ALREADY_SCANNED,
            risk_signals=signals,
        )
    if claim is ScanClaim.APPROVED_MINE:
        return _Scanned(_scan_context_response(code), repeat_detail=DETAIL_ALREADY_APPROVED)
    if claim is ScanClaim.CONFLICT_REVOKED or claim is ScanClaim.CONFLICT_EXCHANGED:
        # A LOG LINE AS WELL AS THE ROW, because this is the event an operator
        # may want to alert on at the edge. The handle, never the code.
        logger.warning(
            "device scan: pairing %s scanned by a second customer (%s)",
            device_code_handle(code.device_code),
            claim.value,
        )
        if claim is ScanClaim.CONFLICT_EXCHANGED and not await _recall(request, audit, code=code):
            return _Scanned(_recall_retry_response(), DETAIL_SCAN_CONFLICT)
        return _Scanned(_scan_conflict_response(), DETAIL_SCAN_CONFLICT)
    return _Scanned(_unpairable_response(), DETAIL_USER_CODE_NOT_FOUND)


#: What a recall answers 503 for: a store that was out or contended, which an
#: immediate retry can get past. Anything else is a 500 (see `_recall`).
_RECALL_FAILURES: tuple[type[Exception], ...] = (
    *SESSION_STORE_OUTAGES,
    RevocationStoreUnavailable,
    RefreshSessionStoreContended,
)


async def _recall(request: Request, scan_audit: PairingAudit, *, code: DeviceCode) -> bool:
    """Recall the session a session swap produced, write its row, and say if it held.

    Spec section 7. Customer B scanned victim A's QR first and approved; A's
    AI client exchanged and holds a session for B's accounts; A's scan is this
    request. In order:

    1. RE-READ THE ROW. ``code`` was read before ``claim_scan``, possibly
       before the exchange, and ``session_id`` is written in the same
       compare-and-set as ``exchanged_at``.
    2. REVOKE THE FAMILY FIRST, so it cannot refresh into a ``jti`` step 3
       never names; ``revoke`` returns every live access ``jti``.
    3. LIST EACH ACCESS TOKEN on the ZT-7 store, which ``services/api``
       checks on every ``tools/call`` and ``tools/list``.

    The row names the family's customer (B), shares the scan row's
    ``call_id``, and is ``returned`` only when the family was revoked and
    every ``jti`` reached a shared store. Returns ``False`` when a store was
    out or contended (``SESSION_STORE_OUTAGES``, ``RevocationStoreUnavailable``,
    ``RefreshSessionStoreContended``), and the caller answers a 503 the app
    retries at once; ``True`` otherwise, including the rows that record
    nothing to recall. ANY OTHER EXCEPTION PROPAGATES, unrecorded here, to the
    500 ``scan_callback`` records under its type: a programming error is not
    an outage, and a retry would only repeat it. An audit write failure
    raises the same way: a revocation that happened is the safe state, so
    nothing is withdrawn.

    A CANCELLATION INSIDE THE STEPS ESCAPES every handler and leaves no row,
    and possibly a half-done recall. Accepted: the family is revoked before
    any ``jti`` is listed, so the state left is either untouched or revoked
    with tokens still to list, and the app's retry repeats ``revoke`` on the
    revoked family, gets the same jtis back and finishes the listing.
    """
    settings: ConfirmSettings = request.app.state.settings
    subject = code.scanned_by
    sid = ""
    detail: str | None = None
    held = True
    try:
        row = await request.app.state.device_code_store.get_device_code(code.device_code)
        if row is not None:
            subject = row.customer_ref or subject
            sid = row.session_id
        sessions: RefreshSessionStoreBase = request.app.state.refresh_session_store
        jtis = await sessions.revoke(sid, reason="recall") if sid else None
        if jtis is None:
            detail = DETAIL_RECALL_NO_SESSION
        else:
            await _reassert(revocation_store(request), jtis)
            if request.app.state.process_local_sessions:
                detail = DETAIL_RECALL_LOCAL_ONLY
    except _RECALL_FAILURES as exc:
        # Recorded and answered 503; the app retries.
        detail = type(exc).__name__
        held = False
        logger.error(
            "device scan: recalling the session of pairing %s failed with %s; the session "
            "may still be live",
            device_code_handle(code.device_code),
            detail,
        )
    recall = PairingAudit(
        db=request.app.state.postern_database,
        call_id=scan_audit.call_id,
        at=datetime.now(UTC),
        started=time.monotonic(),
        subject=subject,
        claims={},
        client_ip_value=pairing_client_ip(request, settings.trusted_proxy_hops),
        tool_name=RECALL_TOOL_NAME,
        route=SCAN_ROUTE,
    )
    recall.names(
        device_code=code.device_code, session_id=sid or None, paired_client_id=code.client_id
    )
    if detail is None:
        await recall.recalled()
    else:
        await recall.refused(detail)
    return held


async def _pairing_network_signals(
    request: Request, creator_ip: str | None, scanner_ip: str | None
) -> list[dict[str, Any]]:
    """The one-element ``risk_signals`` array a successful scan's row carries.

    Where the pairing was created against where it was scanned
    (``postern_core.risk.pairing_network``), with the ASN and country matches
    when an enricher is installed and without those keys when none is. It
    refuses nothing and changes no response: the 200 body is the same for
    every relation and every enrichment outcome.

    MUST NOT RAISE AN ``Exception``. ``scan_callback``'s exception branch
    records a refusal and withdraws nothing, on the premise that nothing after
    a successful claim can raise. ``classify`` and ``compare_facts`` are total
    and ``_enriched_matches`` turns every lookup failure into ``"unknown"``,
    which is what keeps that premise true. A ``CancelledError`` from outside
    is not converted: ``_scan`` withdraws the claim for it.
    """
    settings: ConfirmSettings = request.app.state.settings
    relation = classify(creator_ip, scanner_ip)
    enricher: NetworkEnricher | None = request.app.state.pairing_network_enricher
    if enricher is None:
        signal = pairing_network_signal(relation, settings.trusted_proxy_hops)
    else:
        asn_match, country_match = await _enriched_matches(
            enricher,
            request.app.state.pairing_network_slots,
            relation,
            creator_ip,
            scanner_ip,
            budget=settings.pairing_enricher_timeout_seconds,
        )
        signal = pairing_network_signal(
            relation, settings.trusted_proxy_hops, asn_match, country_match
        )
    return [signal_to_json(signal)]


_UNKNOWN_MATCHES: tuple[MatchResult, MatchResult] = ("unknown", "unknown")


def _enrichment_failed(reason: str) -> tuple[MatchResult, MatchResult]:
    """One WARNING, then ``"unknown"`` for both matches.

    ``reason`` is ``timeout``, ``saturated``, ``wrong_type`` or an exception's
    type name, and nothing else: no ``exc_info``, no exception message and no
    traceback, because a provider's message can quote the address it was
    asked about, and never either address.
    """
    logger.warning("pairing network enrichment: %s", reason)
    return _UNKNOWN_MATCHES


def _failure_name(exc: Exception) -> str:
    """The type name to log, looking through the group a ``TaskGroup`` raises."""
    while isinstance(exc, ExceptionGroup) and exc.exceptions:
        exc = exc.exceptions[0]
    return type(exc).__name__


async def _enriched_matches(
    enricher: NetworkEnricher,
    slots: asyncio.Semaphore,
    relation: NetworkRelation,
    creator_ip: str | None,
    scanner_ip: str | None,
    *,
    budget: float,
) -> tuple[MatchResult, MatchResult]:
    """``(asn_match, country_match)`` from the enricher, under the budget and the cap.

    NO LOOKUP FOR ``unknown``: there is no pair to compare. ONE for
    ``same_ip``, for that one address, passed to ``compare_facts`` on both
    sides so a match is ``True`` only for a field the provider returned. TWO
    otherwise, concurrently, inside one ``asyncio.timeout``; a lookup that
    finished while the other did not is discarded, because a comparison needs
    both sides.

    THE CAP DOES NOT WAIT. ``slots.locked()`` and ``async with slots`` have no
    ``await`` between them, so on one event loop the check cannot race, and a
    scan that finds every slot taken records ``"unknown"`` at once.

    A PROVIDER'S OWN ``CancelledError`` IS A FAILED LOOKUP. Raised from inside
    ``lookup`` it reaches here directly on the one-lookup path and through the
    finished task's ``result()`` on the two-lookup path, and in both cases
    this task's ``cancelling()`` is 0: nobody asked to cancel the request, so
    withdrawing the claim for it would end a legitimate pairing. It records
    ``"unknown"`` under the reason ``CancelledError``. A cancellation of the
    request itself leaves ``cancelling()`` above 0 and still propagates, to
    ``_scan``'s withdrawal.

    WHAT THE BUDGET CANNOT STOP. ``asyncio.timeout`` cancels only at an
    ``await`` that yields. A ``lookup`` that never yields, or calls blocking
    I/O inside ``async def``, holds the loop for every request on the replica
    and the budget fires only after it returns. Nothing in this process can
    prevent that short of a subprocess, which is why the provider contract
    requires async I/O throughout.
    """
    # THE ADDRESS `classify` COMPARED, not the stored string: an IPv4-mapped
    # or zoned form is looked up as the address the relation was computed from.
    creator = normalised_address(creator_ip)
    scanner = normalised_address(scanner_ip)
    if relation is NetworkRelation.UNKNOWN or creator is None or scanner is None:
        return _UNKNOWN_MATCHES
    if slots.locked():
        return _enrichment_failed("saturated")
    answers: list[object]
    async with slots:
        try:
            async with asyncio.timeout(budget):
                if relation is NetworkRelation.SAME_IP:
                    one = await enricher.lookup(scanner)
                    answers = [one, one]
                else:
                    async with asyncio.TaskGroup() as group:
                        creator_lookup = group.create_task(enricher.lookup(creator))
                        scanner_lookup = group.create_task(enricher.lookup(scanner))
                    answers = [creator_lookup.result(), scanner_lookup.result()]
        except TimeoutError:
            return _enrichment_failed("timeout")
        except asyncio.CancelledError:
            # The provider's own, or the request's? Only an outer cancellation
            # leaves this task with a pending cancel request; the budget's has
            # already been uncancelled and turned into `TimeoutError` above.
            task = asyncio.current_task()
            if task is not None and task.cancelling() == 0:
                return _enrichment_failed("CancelledError")
            raise
        except Exception as exc:  # noqa: BLE001 -- every provider failure is "unknown"
            return _enrichment_failed(_failure_name(exc))
    facts: list[NetworkFacts | None] = []
    discarded = False
    for answer in answers:
        if answer is None:
            facts.append(None)
            continue
        if not isinstance(answer, NetworkFacts):
            return _enrichment_failed("wrong_type")
        cleaned, dropped = sanitised(answer)
        discarded = discarded or dropped
        facts.append(cleaned)
    if discarded:
        logger.warning("pairing network enrichment: invalid_field")
    return compare_facts(facts[0], facts[1])


# ---------------------------------------------------------------------------
# Route assembly.
# ---------------------------------------------------------------------------


def device_auth_routes(
    store: DeviceCodeStoreBase,
    settings: ConfirmSettings,
) -> list[Route]:
    """Build the device authorization route list.

    Args:
        store: Device code storage backend.
        settings: Service settings (TTL, URIs, poll interval).

    NO MINTER AND NO FAMILY STORE. The handlers read the session minter and
    the refresh-family store from ``app.state``, where ``create_confirm_app``
    puts them, as they read the device code store; a parameter nothing reads
    would only look like wiring. The read minter this took until the layer-1
    session token went the same way.

    Returns:
        Starlette Route objects to mount on the confirm service app.

    No ``write_minter``. Since ``/token`` stopped returning a write token
    (audit finding C-01), nothing on this path signs with the write key, and
    the argument went with the code that used it. ``main.py`` no longer
    reaches through ``WriteTokenMinter._minter`` to build this list either.
    """
    return [
        Route(
            "/device_authorization",
            device_authorization,
            methods=["POST"],
        ),
        Route(
            "/token",
            token_endpoint,
            methods=["POST"],
        ),
        Route(
            "/scan",
            scan_callback,
            methods=["POST"],
        ),
        Route(
            "/approve",
            approve_callback,
            methods=["POST"],
        ),
    ]


# ---------------------------------------------------------------------------
# Factory — picks the right backend based on environment.
# ---------------------------------------------------------------------------


def build_device_code_store() -> DeviceCodeStoreBase:
    """Create a device code store from environment.

    Reads ``POSTERN_REDIS_URL``: if set, returns a Redis-backed store;
    otherwise returns an in-memory store.

    This mirrors ``postern_core.risk.session.create_session_store``'s pattern.
    """
    return create_device_code_store()

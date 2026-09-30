"""RFC 8628 device authorization endpoints for the confirm service.

Endpoints:
- ``POST /device_authorization`` — Generate device code + QR pairing data.
- ``POST /token`` with ``grant_type=device_code`` — Exchange device code for
  tokens (polling; returns error until mobile app approves).
- ``POST /scan`` -- Mobile app scan of the QR (binds the pairing to the first
  customer who presents a current rotation token).
- ``POST /approve`` — Mobile app approval callback (marks device code as
  approved).

The confirm service is the right home for these because:
1. It holds the READ key the device grant needs to mint the browser's access
   token (a controlled exception to the key-split architecture — see
   ``ConfirmSettings`` docstring).
2. The approval callback needs to update device code state, which lives in
   the same service as the token minting.

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
``customer_ref`` stored on the device code, before the read token is minted.
Nothing is keyed on ``DeviceCode.client_id`` -- the browser supplies it
unauthenticated at ``POST /device_authorization``, so a kill switch enforced
on it would be theatre. ``services/confirm/revocation.py`` holds the full
argument.

WHAT THIS MODULE NO LONGER DOES. It used to take the customer identity from
``/approve``'s request body (``subject_value``) and it used to return a
WRITE-signed token from ``/token``. Together those made three unauthenticated
calls sufficient to obtain ``aud=payments.svc scope=payments:execute`` for any
customer named in a JSON body. Both are gone: the identity comes from a
verified assertion, and ``/token`` returns a read token only. A write token is
minted inside the approval path in ``services/confirm/callback.py``, where it
is used and discarded, and is never serialized to an HTTP client.

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
    routes = device_auth_routes(
        store=store,
        settings=settings,
        read_minter=read_minter,
    )
"""

from __future__ import annotations

import dataclasses
import json
import logging
import time
import uuid
from datetime import UTC, datetime, timedelta
from typing import Literal

from postern_core.auth.device_codes import (
    DeviceCode,
    DeviceCodeStoreBase,
    DeviceCodeStoreContended,
    DeviceCodeStoreFull,
    ScanClaim,
    create_device_code_store,
)
from postern_core.auth.internal_jwt import InternalTokenMinter
from postern_core.auth.revocation import RevocationStoreUnavailable
from postern_core.identity import CustomerRef
from postern_core.store.engine import Database
from pydantic import ValidationError
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from services.confirm.audit import (
    DETAIL_ALREADY_APPROVED,
    DETAIL_DEVICE_CODE_SPENT,
    DETAIL_INVALID_SUBJECT,
    DETAIL_NOT_SCANNED,
    DETAIL_QR_INVALID,
    DETAIL_QR_STALE,
    DETAIL_REVOKED,
    DETAIL_SCAN_CONFLICT,
    DETAIL_SCANNED_BY_OTHER,
    DETAIL_STORED_IDENTITY_MALFORMED,
    DETAIL_USER_CODE_NOT_FOUND,
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
    log_refusal,
    revoked_response,
    store_unavailable_response,
)
from services.confirm.settings import DEFAULT_DEVICE_SCOPES, ConfirmSettings

logger = logging.getLogger(__name__)

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
        try:
            body = await request.json()
        except (json.JSONDecodeError, UnicodeDecodeError):
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
            # RECORDED AND READ BY NOTHING YET. The creator-versus-scanner
            # comparison that would use it is a later spec's; recording it
            # now is what gives that spec something to compare. Under the
            # default of zero trusted hops this is the direct peer, which
            # behind a load balancer is the balancer's address.
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


def _poll_times(request: Request) -> dict[str, datetime]:
    """Per-device-code time of the last pending poll, for RFC 8628 ``slow_down``.

    Keyed by the raw device code and never leaves the process: not logged,
    not serialised. Only codes the store holds are ever recorded, and entries
    are swept once older than ``device_code_ttl_seconds`` (see
    ``token_endpoint``), so the map is bounded by the live-code population.
    """
    poll_times: dict[str, datetime] | None = getattr(request.app.state, "_poll_times", None)
    if poll_times is None:
        poll_times = {}
        request.app.state._poll_times = poll_times
    return poll_times


def _drop_poll_time(request: Request, device_code_value: str) -> None:
    _poll_times(request).pop(device_code_value, None)


async def token_endpoint(request: Request) -> JSONResponse:
    """Spend a device code for one read token, and record the mint.

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

    Handles ``grant_type=device_code`` (RFC 8628 §3.4) and forwards all
    other grant types to the existing JWKS-only app (which will 404).

    Request body:
        grant_type: "device_code" (required for this path).
        device_code: The opaque device code from /device_authorization.

    Response while pending (400):
        {"error": "authorization_pending", "error_description": "..."}

    Response after approval (200):
        {
            "access_token": "<read token>",
            "token_type": "Bearer",
            "expires_in": 60,
        }

    There is no ``write_token`` in that response and there must never be one
    again (audit finding C-01). This endpoint is public and its only
    credential is the ``device_code``, so anything it returns is reachable by
    whoever holds that value; a token with ``aud=payments.svc`` and
    ``scope=payments:execute`` is not something to put behind a single bearer
    secret polled over HTTP. The write path mints its own token inside
    ``services/confirm/callback.py``, per request, and never hands one out.

    Error codes per RFC 8628 §3.4:
        authorization_pending — not yet approved, keep polling.
        slow_down — client is polling too fast (adds 5s to interval).
        access_denied — user explicitly denied on mobile app, OR the customer
            who approved this code has been revoked (ZT-7). The two are
            deliberately indistinguishable here; see the comment at the check.
        expired_token — device code has passed its TTL.

    And two that are RFC 6749 §5.2's, because RFC 8628 has no code for either:
        invalid_grant — the code is unknown, or a previous exchange already
            spent it, or a concurrent one is spending it. One body for all
            three, so the response is not an oracle; ``_unredeemable_response``
            above carries why this code and not one of the four.
        temporarily_unavailable — the revocation store could not be consulted,
            so nothing was minted and nothing was spent. Answered 503 and
            retryable on purpose.

    WHAT IS RECORDED, AND HOW LITTLE OF IT. This endpoint wrote no
    ``audit_log`` row until 2026-09-26, which left the device grant's chain
    with a hole in the middle: the pairing was recorded, the tool calls the
    minted token made were recorded twice each, and the mint between them was
    invisible. It now writes exactly one row on each of SIX exits -- the mint, a
    ZT-7 refusal, a stored identity that will not parse, a revocation store that
    could not answer, and the two ways a spent code is refused -- and nothing on
    the other seven. Both spent exits carry ``DETAIL_DEVICE_CODE_SPENT``,
    because they are one conclusion reached at two places.

    THOSE TWO COUNTS ARE RE-DERIVED AND THE OLD ONES WERE WRONG. This paragraph
    said "FOUR exits ... the other six" when four was right, and six was not:
    there were seven unrecorded exits then and there are seven now, since the
    two this change adds are both recorded. Counted from the ``return``
    statements of this function and ``_exchange`` together on 2026-09-26, which
    is the only way to count them -- ``_exchange`` is where half the endpoint's
    exits live.

    EVERY UNRECORDED EXIT IS ONE THAT RESOLVED NOBODY, and that is the rule
    rather than a list: ``services/confirm/audit.py``'s ``PairingAudit`` owes a
    row only where the server resolved an identity and then decided something
    about its authority. ``customer_ref`` is read off the device code AFTER the
    grant type, the code lookup, the expiry check and the approval check, so a
    wrong grant type, a missing or unknown ``device_code``, an expired code,
    ``slow_down`` and ``authorization_pending`` are all answered before any
    identity exists. That is what keeps this table from becoming a log of a
    browser waiting: at the configured 5-second interval and 900-second
    lifetime a poll loop can run 180 times and write nothing.

    NOTHING OF THE TOKEN GOES ANYWHERE. Not the string, not a segment of it,
    not a digest. The row says a token was minted for this customer off this
    device code at this instant; ``services/api``'s own two rows per tool call
    say what was then done with it.
    """
    at = datetime.now(UTC)
    started = time.monotonic()

    form = await request.form()
    grant_type_raw = form.get("grant_type", "")
    grant_type: str = (
        grant_type_raw.file.read().decode()
        if hasattr(grant_type_raw, "file")
        else str(grant_type_raw)
    )

    if grant_type != "device_code":
        # Not a device code request — let the 404 handler deal with it.
        return _error(404, "unsupported_grant_type", "only device_code grant is supported")

    device_code_raw = form.get("device_code", "")
    device_code_value: str = (
        device_code_raw.file.read().decode()
        if hasattr(device_code_raw, "file")
        else str(device_code_raw)
    )
    if not device_code_value:
        return _error(400, "invalid_request", "device_code is required")

    store: DeviceCodeStoreBase = request.app.state.device_code_store
    settings: ConfirmSettings = request.app.state.settings

    code: DeviceCode | None = await store.get_device_code(device_code_value)
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
        await store.revoke_device_code(device_code_value)
        _drop_poll_time(request, device_code_value)
        return _error(400, "expired_token", "device code has expired")

    # RFC 8628 §3.4 — "slow_down": client is polling faster than the
    # ``interval`` parameter. Only enforced while authorization is pending;
    # once approved the client should get tokens immediately.
    if not code.approved:
        poll_times = _poll_times(request)
        last_poll = poll_times.get(device_code_value)
        if last_poll is not None:
            elapsed = (datetime.now(UTC) - last_poll).total_seconds()
            if elapsed < settings.device_poll_interval_seconds:
                return _error(
                    400,
                    "slow_down",
                    f"Poll again in {int(settings.device_poll_interval_seconds - elapsed)}s",
                )
        # Record this poll time. Pop first so the dict stays ordered by last
        # poll, then sweep from the front: nothing outlives the code's TTL,
        # and the sweep is amortised O(1) per poll.
        now = datetime.now(UTC)
        poll_times.pop(device_code_value, None)
        poll_times[device_code_value] = now
        horizon = now - timedelta(seconds=settings.device_code_ttl_seconds)
        while True:
            oldest = next(iter(poll_times))
            if poll_times[oldest] >= horizon:
                break
            del poll_times[oldest]
    else:
        # Approved: the interval no longer applies, so the entry is dead.
        _drop_poll_time(request, device_code_value)

    if not code.approved:
        return _error(400, "authorization_pending", "waiting for user approval on mobile app")

    # Approved — mint the read token, and only the read token.
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
    # beyond the code itself. So the row says "a token was minted for this
    # customer", never "this customer asked for it".
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
                audit_exc,
                exc_info=audit_exc,
            )
            raise exc from audit_exc
        raise

    # THE ROW IS COMMITTED BEFORE THE RESPONSE IS RETURNED, and on the success
    # path that means before the token is serialised to anybody. A raise here
    # drops `response` -- the minted string goes out of scope unreferenced and
    # reaches no caller, no store and no log -- so "no row" means no token ever
    # left this process. `PairingAudit`'s "FAIL CLOSED AT A MINT" section
    # carries why neither of the two obvious orders works and what the
    # residual is. Do not move this below the `return`.
    try:
        if detail is None:
            await audit.minted()
        else:
            await audit.refused(detail)
    except Exception as audit_exc:
        logger.error(
            "audit write failed for a device-grant token exchange that answered %d; "
            "failing the request, so nothing it minted reaches the caller",
            response.status_code,
            exc_info=audit_exc,
        )
        raise
    return response


async def _exchange(
    request: Request,
    audit: PairingAudit,
    *,
    code: DeviceCode,
) -> tuple[JSONResponse, str | None]:
    """The spend, the ZT-7 check and the mint, returning ``(response, detail)``.

    ``detail`` is ``None`` when a token was minted and one of
    ``services/confirm/audit.py``'s ``DETAIL_*`` literals otherwise. Split out
    from ``token_endpoint`` so the row is written in exactly one place, which
    is the same division ``approve_callback`` and
    ``services/confirm/callback.py`` both make.

    THE ORDER OF THE THREE IS DECIDED, and two of the three orders are wrong.

    The spent check comes FIRST because a code that can never be redeemed again
    must not be answered with a retryable code. Put it after the ZT-7 check and
    a replay arriving while the revocation store is down is answered 503
    ``temporarily_unavailable``, which tells the browser to come back for a
    grant no retry will ever redeem; it would poll a dead code until it
    expired.

    The CLAIM comes after the ZT-7 check, which is the opposite ordering, and
    for the mirror-image reason: the claim is irreversible and 503 means the
    server failed to decide. Claiming first would spend a legitimate
    customer's code on a revocation-store outage, so their retry -- the one the
    503 invited -- would be refused, and it would hand anyone holding a leaked
    code a way to destroy a pairing during an outage. Nothing is spent on a
    question this service could not answer.

    So the spent check and the claim are the same property asked twice, and
    they are not redundant: the first refuses a code an EARLIER request spent
    and needs no round trip, the second refuses one a CONCURRENT request is
    spending and is the only one of the two that can. Both answer with the same
    response and the same ``detail``.
    """
    store: DeviceCodeStoreBase = request.app.state.device_code_store
    device_code_value = code.device_code

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
    except RevocationStoreUnavailable as exc:
        logger.warning("device grant: revocation store unavailable, refusing to mint")
        return store_unavailable_response(), type(exc).__name__
    if revoked:
        log_refusal("a device-grant token exchange")
        return _error(400, "access_denied", "authorization was refused"), DETAIL_REVOKED

    # SPEND THE CODE BEFORE SIGNING ANYTHING. One approved device code is
    # worth one read token, and this line is where that becomes true rather
    # than intended: `postern_core.auth.device_codes`'s ``consume_device_code``
    # answers ``True`` to exactly one caller, so a burst of concurrent polls
    # mints once and the rest arrive here having lost.
    #
    # BEFORE THE MINT AND NOT AFTER. Claiming afterwards would have every
    # racing request sign a credential and all but one throw it away, which is
    # a signing key used for work this service has already decided not to
    # honour. Nothing is signed that this request is not entitled to sign.
    #
    # A LOST CLAIM IS NOT UNDONE, HERE OR ANYWHERE. If the mint below raises,
    # or `token_endpoint`'s audit write does, the code stays spent and the
    # customer starts again from a fresh QR -- the direction
    # ``_withdraw_pairing`` already chose one endpoint earlier, for the same
    # reason: a device code is in this deployment's own store, so refusing and
    # making them re-pair costs a scan, while leaving a redeemable code behind
    # a 500 is fail-open in substance.
    if not await store.consume_device_code(device_code_value):
        return _unredeemable_response(), DETAIL_DEVICE_CODE_SPENT

    read_minter: InternalTokenMinter = request.app.state.read_minter
    read_token = read_minter.mint(
        subject=customer,
        audience="accounts.svc",
        scope="accounts:read",
    )

    # THE TOKEN IS IN THIS RESPONSE OBJECT AND NOWHERE ELSE YET. It is not
    # logged, not stored and not returned to a caller until `token_endpoint`
    # has committed the row, which is what makes dropping this object the undo
    # a mint would otherwise not have.
    return (
        JSONResponse(
            status_code=200,
            content={
                "access_token": read_token,
                "token_type": "Bearer",
                "expires_in": 60,
            },
        ),
        None,
    )


# ---------------------------------------------------------------------------
# Approval callback — POST /approve.
#
# Called by the operator's banking app after the user has scanned the QR
# (``POST /scan``), compared the pairing codes and completed identity
# verification. It marks the device code approved so the browser can exchange
# it for a read token.
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
    scanned, and one already approved. Byte for byte the same, for the reason
    ``_unredeemable_response`` gives at ``POST /token``: the distinction the
    caller does not get is exactly the one an operator needs, so it lives in
    ``audit_log.detail`` and nowhere a caller can read it.

    ``invalid_grant`` is RFC 6749 section 5.2's code for a grant that is
    "invalid, expired, revoked", which is true of every case above.
    """
    return _error(400, "invalid_grant", "this pairing cannot be completed")


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
    #: pairing.
    detail: str | None = None
    #: Whether this exit owes a row at all. ``False`` is the other half of
    #: ``PairingAudit``'s rule: a malformed request is answered by looking at
    #: the request and consulting nothing, so it concluded nothing to record.
    recorded: bool = True
    #: The device code this exit APPROVED, so the caller can withdraw the
    #: pairing if the row cannot be written. ``None`` wherever nothing was
    #: approved, which is every exit but one.
    approved_device_code: str | None = None


async def approve_callback(request: Request) -> JSONResponse:
    """Banking app approval callback for a device pairing, and its audit row.

    Requires a verified app assertion (``services/confirm/auth.py``). The
    customer is the assertion's ``sub``.

    Request body:
        user_code: The pairing code the app read from the scanned QR,
            ``XXX-XXX`` or bare. A body that also carries ``device_code`` is
            refused.

    Response (200): ``{"status": "approved"}``
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
                audit_exc,
                exc_info=audit_exc,
            )
            raise exc from audit_exc
        raise

    if not outcome.recorded:
        return outcome.response

    try:
        if outcome.detail is None:
            await audit.approved()
        else:
            await audit.refused(outcome.detail)
    except Exception as audit_exc:
        # FAIL CLOSED, AND HERE THAT MEANS UNDOING THE PAIRING. One endpoint
        # over the same failure can only be reported, because the money has
        # already moved and this process cannot unmove it. A pairing is in
        # this deployment's own store, so leaving it standing behind a 500
        # would be fail-closed in the response and fail-open in substance:
        # the browser polls `/token`, is handed a read token, and no row
        # anywhere names who authorised it. `PairingAudit` carries the full
        # argument and what the availability cost is.
        if outcome.approved_device_code is not None:
            await _withdraw_pairing(
                store, outcome.approved_device_code, cause="audit", state="approved"
            )
        logger.error(
            "audit write failed for a device pairing that answered %d; "
            "failing the request because the pairing could not be recorded",
            outcome.response.status_code,
            exc_info=audit_exc,
        )
        raise
    return outcome.response


async def _withdraw_pairing(
    store: DeviceCodeStoreBase,
    device_code_value: str,
    *,
    cause: Literal["audit", "store"],
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

    ``cause`` and ``state`` say which of the four callers this is, because
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
                revoke_exc,
                exc_info=revoke_exc,
            )
        else:
            logger.error(
                "a device pairing's store write failed ambiguously AND it could not be "
                "withdrawn; device code %s may be %s while its audit_log row "
                "records a refusal: %s",
                device_code_handle(device_code_value),
                state,
                revoke_exc,
                exc_info=revoke_exc,
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
    reads after a refusal labels the audit row and decides nothing.
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
        body = await request.json()
    except (json.JSONDecodeError, UnicodeDecodeError):
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
        return _Pairing(
            JSONResponse(status_code=200, content={"status": "approved"}),
            approved_device_code=existing.device_code,
        )

    return _Pairing(
        _unpairable_response(),
        await _approve_refusal_detail(store, existing.device_code, customer.value),
    )


async def _approve_refusal_detail(
    store: DeviceCodeStoreBase, device_code_value: str, customer_ref: str
) -> str:
    """Which ``DETAIL_*`` a refused ``approve_scanned`` is recorded under.

    Read from the row AFTER the compare-and-set refused, in the order
    ``dev-docs/qr-page-spec.md`` section 6 fixes: gone or expired by now,
    then nobody scanned it, then somebody else did, then it is already
    approved. The read decides nothing -- the refusal has happened -- so the
    race between the two reads can only move a row from one label to another,
    never approve anything.

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
    The exception's type goes to a WARNING instead. ``Exception`` and not
    ``BaseException``, so a cancelled request still stops.
    """
    try:
        row = await store.get_device_code(device_code_value)
    except Exception as exc:
        logger.warning(
            "device approve: re-reading a refused pairing failed with %s; "
            "recording it as not_scanned",
            type(exc).__name__,
        )
        return DETAIL_NOT_SCANNED
    if row is None or row.is_expired:
        return DETAIL_USER_CODE_NOT_FOUND
    if not row.scanned_by:
        return DETAIL_NOT_SCANNED
    if row.scanned_by != customer_ref:
        return DETAIL_SCANNED_BY_OTHER
    if row.approved:
        return DETAIL_ALREADY_APPROVED
    return DETAIL_NOT_SCANNED


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


async def scan_callback(request: Request) -> JSONResponse:
    """The banking app's scan of a pairing QR, and its audit row.

    Requires a verified app assertion (``services/confirm/auth.py``); it is
    not in ``PUBLIC_PATHS``. The customer is the assertion's ``sub``.

    Request body:
        user_code: From the app link the QR encodes, ``XXX-XXX`` or bare.
        qr: The rotation token from the same link, ``<slot>.<mac>``.

    Response (200): the stored pairing's context; see ``_scan_context_response``.
    Response (400): ``invalid_request`` for a malformed body; ``qr_stale``;
        ``scan_conflict``; and the one ``invalid_grant`` body of
        ``_unpairable_response`` for an unknown or expired code, an approved
        one, and a malformed, forged or future rotation token.
    Response (401): no verified assertion.
    Response (403): ``invalid_subject`` or ``access_revoked`` (ZT-7).

    ONE ROW PER RECORDED CALL, through ``PairingAudit`` with
    ``SCAN_TOOL_NAME`` and ``SCAN_ROUTE``, fail-closed per decision 0006: a
    claim whose row cannot be written is withdrawn exactly as
    ``_withdraw_pairing`` withdraws an unrecorded approval. The malformed-body
    exits write nothing, by ``PairingAudit``'s rule, as on ``POST /approve``.
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

    audit = PairingAudit(
        db=db,
        call_id=str(uuid.uuid4()),
        at=at,
        started=started,
        subject=subject,
        claims=verified_claims(request),
        client_ip_value=pairing_client_ip(request, settings.trusted_proxy_hops),
        tool_name=SCAN_TOOL_NAME,
        route=SCAN_ROUTE,
    )

    try:
        outcome = await _scan(request, audit, store=store, subject=subject)
    except Exception as exc:
        # The shape `approve_callback` uses: an audit-write failure must not
        # replace the exception that ended the request.
        #
        # A RAISE MAY FOLLOW A COMMITTED CLAIM. On Redis `claim_scan`'s
        # `pipe.execute()` can raise after the server ran `EXEC`, so `_scan`
        # withdraws the pairing before that exception reaches this branch,
        # exactly as `_pair` does for `approve_scanned`. Nothing else in
        # `_scan` writes, and nothing after a successful claim can raise, so
        # there is nothing left to withdraw here.
        try:
            await audit.refused(type(exc).__name__)
        except Exception as audit_exc:
            logger.error(
                "audit write failed for a device pairing scan after it raised %s: %s",
                type(exc).__name__,
                audit_exc,
                exc_info=audit_exc,
            )
            raise exc from audit_exc
        raise

    if not outcome.recorded:
        return outcome.response

    try:
        if outcome.detail is None:
            await audit.approved()
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
            "failing the request because the scan could not be recorded",
            outcome.response.status_code,
            exc_info=audit_exc,
        )
        raise
    return outcome.response


async def _scan(
    request: Request,
    audit: PairingAudit,
    *,
    store: DeviceCodeStoreBase,
    subject: str,
) -> _Scanned:
    """The scan itself, in section 5's order, returning what the row owes.

    THE MAC IS CHECKED BEFORE THE CLAIM, and that order is what keeps session
    swap detection honest. A stale token from a second customer answers
    ``qr_stale`` and revokes nothing, because only a caller inside the token
    window -- one who could have been standing at the screen -- reaches
    ``claim_scan`` at all.
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
        body = await request.json()
    except (json.JSONDecodeError, UnicodeDecodeError):
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
        claim = await store.claim_scan(code.device_code, customer.value)
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
        return _Scanned(_scan_context_response(code), claimed_device_code=code.device_code)
    if claim is ScanClaim.ALREADY_MINE:
        return _Scanned(_scan_context_response(code))
    if claim is ScanClaim.APPROVED_MINE:
        return _Scanned(_unpairable_response(), DETAIL_ALREADY_APPROVED)
    if claim is ScanClaim.CONFLICT_REVOKED or claim is ScanClaim.CONFLICT_EXCHANGED:
        # A LOG LINE AS WELL AS THE ROW, because this is the event an operator
        # may want to alert on at the edge. The handle, never the code.
        logger.warning(
            "device scan: pairing %s scanned by a second customer (%s)",
            device_code_handle(code.device_code),
            claim.value,
        )
        return _Scanned(_scan_conflict_response(), DETAIL_SCAN_CONFLICT)
    return _Scanned(_unpairable_response(), DETAIL_USER_CODE_NOT_FOUND)


# ---------------------------------------------------------------------------
# Route assembly.
# ---------------------------------------------------------------------------


def device_auth_routes(
    store: DeviceCodeStoreBase,
    settings: ConfirmSettings,
    read_minter: InternalTokenMinter,
) -> list[Route]:
    """Build the device authorization route list.

    Args:
        store: Device code storage backend.
        settings: Service settings (TTL, URIs, poll interval).
        read_minter: Minter for read tokens (during device code exchange).

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

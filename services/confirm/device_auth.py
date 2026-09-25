"""RFC 8628 device authorization endpoints for the confirm service.

Endpoints:
- ``POST /device_authorization`` — Generate device code + QR pairing data.
- ``POST /token`` with ``grant_type=device_code`` — Exchange device code for
  tokens (polling; returns error until mobile app approves).
- ``POST /approve`` — Mobile app approval callback (marks device code as
  approved).

The confirm service is the right home for these because:
1. It holds the READ key the device grant needs to mint the browser's access
   token (a controlled exception to the key-split architecture — see
   ``ConfirmSettings`` docstring).
2. The approval callback needs to update device code state, which lives in
   the same service as the token minting.

QR data encoding: the verification URI with ``user_code`` as a query
parameter (``verification_uri_complete``). The mobile app deep-links to this
URI; the browser shows a QR encoding it.

Pairing code (``user_code``): 6 uppercase alphanumeric chars, displayed as
XXX-XXX on both surfaces. ``POST /approve`` REQUIRES it and compares it, in
constant time, against the code stored for that device code
(``postern_core.auth.device_codes`` records which half of the A2 control that
is and which half only the operator's app can perform).

WHO IS AUTHENTICATED, AND WHO IS NOT. ``POST /approve`` is the banking app,
and it must present a bearer assertion the operator's app backend minted;
``services/confirm/auth.py`` verifies it and this module takes the customer
from the verified ``sub``. ``POST /device_authorization`` and ``POST /token``
are the BROWSER, which by the device grant's premise holds no credential at
all, and they are named in that module's ``PUBLIC_PATHS`` with the reason.

WHO CAN BE CUT, AND WHERE (ZT-7). Both endpoints that know a customer refuse a
revoked one: ``POST /approve`` on the assertion's ``sub``, before the device
code is touched, and ``POST /token`` on the ``customer_ref`` stored on the
device code, before the read token is minted. Nothing is keyed on
``DeviceCode.client_id`` -- the browser supplies it unauthenticated at
``POST /device_authorization``, so a kill switch enforced on it would be
theatre. ``services/confirm/revocation.py`` holds the full argument.

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
import hmac
import json
import logging
from datetime import UTC, datetime

from postern_core.auth.device_codes import (
    DeviceCode,
    DeviceCodeStoreBase,
    DeviceCodeStoreFull,
    create_device_code_store,
)
from postern_core.auth.internal_jwt import InternalTokenMinter
from postern_core.auth.revocation import RevocationStoreUnavailable
from postern_core.identity import CustomerRef
from pydantic import ValidationError
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from services.confirm.auth import unauthenticated_response, verified_subject
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


def _store_full_response(retry_after: int) -> JSONResponse:
    """The 503 ``POST /device_authorization`` answers when the store is full.

    THE SAME SHAPE AND THE SAME ARGUMENT AS
    `services/confirm/revocation.py`'s ``store_unavailable_response``, which
    already chose ``temporarily_unavailable`` with a 503 for the one other
    condition on this path that is neither the caller's fault nor terminal.
    RFC 6749 §4.1.2.1 vocabulary rather than a §5.2 token-endpoint code,
    stated rather than glossed: no §5.2 code means "come back", and inventing
    a private one would be worse. The browser here holds no credential, has
    done nothing wrong, and the honest signal for it is one it can retry.

    ``Retry-After`` carries the device code lifetime, because that is the
    interval after which capacity is guaranteed to have been released: the
    oldest code in a full store expires within one TTL, and
    ``create_device_code`` sweeps before it refuses.

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
        verification_uri_complete: Full URI with user_code (for deep-linking).
        expires_in: Lifetime in seconds.
        interval: Seconds between token polls.

    RFC 8628 §3.1 — the device_code is 40+ chars, user_code is 6+ chars
    of uppercase alphanumeric (no ambiguous characters).

    Response (503): the device code store is at its cap. See
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
        )
    except DeviceCodeStoreFull as exc:
        logger.warning(
            "device authorization refused: the device code store holds %d codes, its cap",
            exc.held,
        )
        return _store_full_response(settings.device_code_ttl_seconds)

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


async def token_endpoint(request: Request) -> JSONResponse:
    """Exchange a device code for access tokens.

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

    And one that is not RFC 8628's, answered with 503:
        temporarily_unavailable — the revocation store could not be consulted,
            so nothing was minted. Retryable on purpose.
    """
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
        return _error(400, "invalid_grant", "device code not found or already revoked")

    if code.is_expired:
        await store.revoke_device_code(device_code_value)
        return _error(400, "expired_token", "device code has expired")

    # RFC 8628 §3.4 — "slow_down": client is polling faster than the
    # ``interval`` parameter. Only enforced while authorization is pending;
    # once approved the client should get tokens immediately.
    if not code.approved:
        poll_times: dict[str, datetime] = getattr(request.app.state, "_poll_times", {})
        if not poll_times:
            request.app.state._poll_times = poll_times
        last_poll = poll_times.get(device_code_value)
        if last_poll is not None:
            elapsed = (datetime.now(UTC) - last_poll).total_seconds()
            if elapsed < settings.device_poll_interval_seconds:
                return _error(
                    400,
                    "slow_down",
                    f"Poll again in {int(settings.device_poll_interval_seconds - elapsed)}s",
                )
        # Record this poll time.
        poll_times[device_code_value] = datetime.now(UTC)

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
        return _error(500, "invalid_state", "approval missing customer identity")

    try:
        customer = CustomerRef(value=stored_customer_ref)
    except ValidationError:
        # Never let this one propagate. `CustomerRef` sets
        # `hide_input_in_errors=True`, which covers `str()` and `repr()` of the
        # exception but NOT its `errors()` output or `.json()` -- both still
        # carry the raw offending value, and an unhandled exception here is
        # logged by whatever sits above us. A fixed string keeps that value out
        # of the log and off the wire.
        logger.warning("device grant: stored customer reference is not well-formed")
        return _error(500, "invalid_state", "approval identity is not a customer reference")

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
    try:
        revoked = await customer_revoked(request, customer.value)
    except RevocationStoreUnavailable:
        logger.warning("device grant: revocation store unavailable, refusing to mint")
        return store_unavailable_response()
    if revoked:
        log_refusal("a device-grant token exchange")
        return _error(400, "access_denied", "authorization was refused")

    read_minter: InternalTokenMinter = request.app.state.read_minter
    read_token = read_minter.mint(
        subject=customer,
        audience="accounts.svc",
        scope="accounts:read",
    )

    return JSONResponse(
        status_code=200,
        content={
            "access_token": read_token,
            "token_type": "Bearer",
            "expires_in": 60,
        },
    )


# ---------------------------------------------------------------------------
# Approval callback — POST /approve.
#
# Called by the operator's banking app after the user completes identity
# verification and confirms the device pairing. It marks the device code
# approved so the browser can exchange it for tokens.
#
# The app sends:
#   device_code — the opaque device code, from the scanned QR.
#   user_code   — the pairing code, from the same QR. REQUIRED and compared.
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


async def approve_callback(request: Request) -> JSONResponse:
    """Banking app approval callback for a device pairing.

    Requires a verified app assertion (``services/confirm/auth.py``). The
    customer is the assertion's ``sub``.

    Request body:
        device_code: The opaque device code (required).
        user_code: The pairing code shown in the QR, ``XXX-XXX`` or bare
            (required — audit finding C-04).

    Response (200): ``{"status": "approved"}``
    Response (400): device code unknown, already approved, or pairing code
        wrong.
    Response (401): no verified assertion.
    Response (403): the assertion verified but its ``sub`` is not a customer
        reference (``invalid_subject``), or that customer's access has been
        revoked (``access_revoked``, ZT-7).
    """
    subject = verified_subject(request)
    if subject is None:
        # Unreachable through the assembled app: `AppAssertionMiddleware`
        # already refused. Reachable if a future route table forgets to wire
        # it, which is how this control would silently stop applying.
        return unauthenticated_response()

    try:
        customer = CustomerRef(value=subject)
    except ValidationError:
        # The assertion is genuine but its subject is not the opaque
        # `cust_...` reference handoff §7.2 requires. That is the operator's
        # app backend minting the wrong claim, not an attacker, and it is
        # worth a distinct status. The raw value is never echoed or logged:
        # see the matching note in `token_endpoint`.
        logger.warning("device approve: assertion subject is not a customer reference")
        return _error(403, "invalid_subject", "assertion subject is not a customer reference")

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
    if await customer_revoked(request, customer.value):
        log_refusal("a device pairing approval")
        return revoked_response("this customer's access has been revoked")

    try:
        body = await request.json()
    except (json.JSONDecodeError, UnicodeDecodeError):
        return _error(400, "invalid_request", "body must be JSON")
    if not isinstance(body, dict):
        return _error(400, "invalid_request", "body must be a JSON object")

    device_code_value = body.get("device_code", "")
    user_code_value = body.get("user_code", "")

    # `isinstance`, not just truthiness. JSON gives a caller ints, lists and
    # objects as easily as strings, and `{"user_code": 123}` would otherwise
    # reach `_normalize_user_code` and raise `AttributeError` -- a 500 from an
    # endpoint that should answer 400. On an authenticated write path a 500 is
    # also the shape that gets "fixed" by relaxing something.
    if not isinstance(device_code_value, str) or not isinstance(user_code_value, str):
        return _error(400, "invalid_request", "device_code and user_code must be strings")

    if not device_code_value or not user_code_value:
        return _error(400, "invalid_request", "device_code and user_code are required")

    store: DeviceCodeStoreBase = request.app.state.device_code_store
    settings: ConfirmSettings = request.app.state.settings

    existing: DeviceCode | None = await store.get_device_code(device_code_value)
    if existing is None:
        return _error(400, "invalid_grant", "device code not found")

    # Checked BEFORE anything is written. A second approval of an already
    # approved code must not reach the write below, or an attacker holding a
    # valid assertion of their own could re-approve a code the victim already
    # approved and swap `customer_ref` to themselves in the window before the
    # browser polls `/token`.
    #
    # This sits BEFORE the `user_code` comparison, and that ordering is a
    # deliberate trade of a small oracle against a real denial of service.
    # Ordered this way, a caller who holds a `device_code` can learn whether
    # it is already approved without proving they hold the pairing code.
    # Ordered the other way, that same caller could burn the attempt budget
    # below on an approved-but-not-yet-exchanged code and REVOKE it, denying
    # the legitimate user the token they are already waiting on. Both
    # presuppose the caller somehow has the 256-bit `device_code`; only one
    # of them destroys a session in flight. Leaking "this code is approved"
    # to someone who already holds the code is the cheaper loss.
    if existing.approved:
        return _error(400, "already_approved", "device code already approved")

    if not _user_code_matches(user_code_value, existing.user_code):
        return await _record_user_code_failure(store, settings, existing)

    # ONE store write carrying approval and identity together. The previous
    # shape was `approve_device_code` and then `update_device_code`, which
    # left a window in which the code read as approved while the identity on
    # it was still the caller-supplied `client_id` -- and `/token` minted
    # from exactly that field. There is no such window now, and `/token`
    # reads `customer_ref`, which is empty until this line runs.
    await store.update_device_code(
        device_code_value,
        dataclasses.replace(
            existing,
            approved=True,
            approved_at=datetime.now(UTC),
            customer_ref=customer.value,
        ),
    )

    return JSONResponse(
        status_code=200,
        content={"status": "approved"},
    )


def _user_code_matches(presented: str, stored: str) -> bool:
    """Constant-time pairing-code comparison.

    ``hmac.compare_digest`` on ``bytes`` rather than ``str``: the ``str``
    overload raises ``TypeError`` on any non-ASCII character, and ``presented``
    is attacker-controlled, so the ``str`` form turns a hostile body into a
    500 instead of a 400.

    Normalizing first is not constant time and leaks the presented length.
    That is accepted: the length of a six-character code from a published
    alphabet is not the secret.
    """
    return hmac.compare_digest(
        _normalize_user_code(presented).encode("utf-8"),
        stored.encode("utf-8"),
    )


async def _record_user_code_failure(
    store: DeviceCodeStoreBase,
    settings: ConfirmSettings,
    existing: DeviceCode,
) -> JSONResponse:
    """Count a wrong pairing code and revoke the device code once over budget.

    RFC 8628 §5.2 asks the authorization server to rate-limit ``user_code``
    attempts. The budget is small (``user_code_max_attempts``, default 3)
    because a legitimate app is comparing a code it just scanned: the only
    benign cause of a mismatch is a user typing it by hand and slipping.

    Revocation rather than a lockout timer, because the recovery the user
    needs is a fresh QR anyway, and a fresh QR is what re-anchors the human
    code comparison that is the real A2 control. A lockout would leave the
    same phishable code on screen.
    """
    attempts = existing.user_code_attempts + 1
    if attempts >= settings.user_code_max_attempts:
        await store.revoke_device_code(existing.device_code)
        logger.warning(
            "device approve: device code revoked after %d incorrect pairing codes", attempts
        )
        return _error(
            400,
            "invalid_user_code",
            "pairing code incorrect; device code revoked, start a new pairing",
        )
    await store.update_device_code(
        existing.device_code,
        dataclasses.replace(existing, user_code_attempts=attempts),
    )
    return _error(400, "invalid_user_code", "pairing code does not match this device code")


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
        settings: Service settings (TTL, URIs, pairing-code attempt budget).
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

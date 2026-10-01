"""Composition root for the write path and device authorization flow.

uvicorn targets ``services.confirm.main:app`` (see the ``confirm`` stage in
the Dockerfile).

Today this process does four things:
1. Hold a write signing key and publish its public half at
   ``/.well-known/jwks.json``, under the write issuer, disjoint from the read
   service's key and issuer. That is the minimum that makes "the tool handler
   cannot reach a backend write endpoint" an infrastructure property: this
   module never imports ``services.api``, and nothing in ``services.api`` can
   reach the key this module holds.
2. Handle RFC 8628 device authorization (§7.3 of the handoff): generate
   device codes, accept banking app approvals, and exchange device codes for
   a read token. The read key here is a controlled exception to the key-split
   architecture; the write key is NOT used on this path at all since audit
   finding C-01 removed the write token from the ``/token`` response.
3. Handle verification challenge approvals (§6.3, §8.3): receive approvals
   from the banking app, mark challenges approved in Postgres, and execute
   backend write endpoints server-side.
4. Serve the browser's pairing page and its QR
   (``services.confirm.verify_page``), the only HTML this repository serves.

ZT-7 revocation reaches every path here that knows a customer: an operator
who revokes a customer stops their challenge approvals, their pairing scans
and approvals and their device-grant token mints as well as their reads.
Which scope reaches this service, and which two do not, is
`services/confirm/revocation.py`'s subject -- the summary is that the write
path can only be keyed on the customer, so **to stop it, name the customer**.

Everything except ``/.well-known/jwks.json``, ``/device_authorization``,
``/token`` and the five routes of the browser's pairing page (``/verify``,
``/verify/qr.svg``, ``/verify/state``, ``/verify.js``, ``/verify.css``)
requires a verified banking-app assertion. ``services/confirm/auth.py`` holds
that middleware, the reasoning for each public path, and the audience
requirement an operator owns. Until 2026-09-22 this app was built as
``Starlette(routes=routes)`` with no ``middleware=`` argument at all and
authenticated nobody on any route.

A challenge approval needs one thing more, since 2026-09-24: an Ed25519
signature from a device the operator enrolled for that customer, over bytes
built from the stored challenge row. The assertion says the operator's APP is
calling for this customer; the signature says the customer's own PHONE did.
``services/confirm/device_signature.py`` holds the check and
`postern_core.auth.device_keys` holds where the keys come from -- and, like
the three assertion settings, this service refuses to start without them.

In front of that sits ``services/confirm/body_limit.py``, which bounds what
any route -- authenticated or public -- will read into memory. Until
2026-09-24 nothing did: ``POST /device_authorization`` read 9,999,989 bytes
and answered 200 with no credential presented at all.

The device authorization endpoints are:
- ``POST /device_authorization`` — Generate device code + QR pairing data.
- ``POST /token`` with ``grant_type=device_code`` — Exchange device code for
  tokens (polling; returns error until mobile app approves).
- ``GET /verify``, ``/verify/qr.svg``, ``/verify/state``, ``/verify.js``,
  ``/verify.css`` -- the browser's pairing page, its QR, its state, its script
  and its stylesheet (``services.confirm.verify_page``).
- ``POST /scan`` -- Mobile app scan of the pairing QR.
- ``POST /approve`` — Mobile app approval callback.

The verification challenge endpoint is:
- ``POST /challenges/{challenge_id}/approve`` — Signed approval for a
  verification challenge (payments, card writes, etc.).

See ``services.confirm.device_auth`` for device auth endpoint implementations
and ``services.confirm.callback`` for the challenge approval handler.
"""

import asyncio
import enum
import logging
from pathlib import Path

from fastmcp.server.auth.providers.jwt import JWTVerifier
from postern_core.auth.device_codes import create_device_code_store
from postern_core.auth.device_keys import DeviceKeyStoreBase, FileDeviceKeyStore
from postern_core.auth.internal_jwt import InternalTokenMinter
from postern_core.auth.keys import choose_key_source
from postern_core.auth.refresh_sessions import create_refresh_session_store
from postern_core.auth.revocation import create_revocation_store
from postern_core.config import enforce_redis_requirement, redis_url_from_env
from postern_core.env_inventory import enforce_known_environment
from postern_core.modules.enrichers import load_network_enricher
from postern_core.risk.pairing_network import NetworkEnricher
from postern_core.store.engine import Database
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.routing import Route
from starlette.types import ASGIApp

from services.confirm.auth import AppAssertionMiddleware, AssertionVerifier
from services.confirm.body_limit import BodySizeLimit
from services.confirm.callback import callback_routes
from services.confirm.customer_rate_limit import (
    CustomerRateLimit,
    create_customer_rate_limit_store,
    customer_limits_from_settings,
)
from services.confirm.device_auth import (
    PAIRING_ENRICHMENT_SLOTS,
    TokenResponseHeaders,
    device_auth_routes,
)
from services.confirm.jwks import jwks_route, session_jwks_route
from services.confirm.minter import build_write_minter
from services.confirm.rate_limit import (
    RATE_LIMIT_WINDOW_SECONDS,
    Limit,
    RateLimit,
    limits_from_settings,
)
from services.confirm.session_token import build_session_minter
from services.confirm.settings import ConfirmSettings, check_session_token_settings
from services.confirm.verify_page import verify_page_routes

logger = logging.getLogger(__name__)


class _FromEntryPoints(enum.Enum):
    """The default of ``create_confirm_app``'s ``network_enricher``.

    A sentinel rather than ``None``, because ``None`` is a meaningful value
    there: "no enricher", which a test passes to build an app that records
    the relation and no match keys whatever is installed.
    """

    LOAD = enum.auto()


def _assertion_verifier(settings: ConfirmSettings) -> AssertionVerifier:
    """The verifier for inbound banking-app assertions, or refuse to start.

    ``services/api/server.py`` guards the same shape and stops one step
    short of this: exactly one of its ``customer_jwks_uri`` /
    ``customer_token_issuer`` pair set is a typo and raises, but NEITHER set
    is a documented no-auth path that returns ``auth=None``, because that
    service must still run under ``docker compose`` with no identity provider
    to serve masked reads.

    This service has no such path and must not grow one. It holds the WRITE
    signing key and its endpoints approve money movement, so "started with no
    authentication" is not a mode worth supporting for convenience -- it is
    the audit finding. All three settings are therefore required, and an
    incomplete configuration fails at startup rather than serving.
    ``ConfirmSettings.for_testing()`` supplies three ``.invalid`` values,
    which build a verifier that refuses every token.
    """
    missing = [
        name
        for name, value in (
            ("app_assertion_jwks_uri", settings.app_assertion_jwks_uri),
            ("app_assertion_issuer", settings.app_assertion_issuer),
            ("app_assertion_audience", settings.app_assertion_audience),
        )
        if not value
    ]
    if missing:
        raise ValueError(
            "the confirm service cannot start without inbound authentication: "
            f"{', '.join(missing)} must be set "
            "(POSTERN_APP_ASSERTION_JWKS_URI, POSTERN_APP_ASSERTION_ISSUER, "
            "POSTERN_APP_ASSERTION_AUDIENCE). There is no unauthenticated mode "
            "on this service; see services/confirm/auth.py."
        )
    return JWTVerifier(
        jwks_uri=settings.app_assertion_jwks_uri,
        issuer=settings.app_assertion_issuer,
        audience=settings.app_assertion_audience,
        required_scopes=None,
    )


def _device_key_store(settings: ConfirmSettings) -> DeviceKeyStoreBase:
    """The enrolled-device keys this service verifies approvals against, or
    refuse to start.

    THE SAME GUARD AS ``_assertion_verifier`` ABOVE, and the same argument.
    Until 2026-09-24 the ``signature`` field on an approval was checked for
    presence and stored; ``services/confirm/device_signature.py`` records what
    that left open. A service that starts without a way to verify it is back
    in that state, so there is no such mode: no default path, no
    warn-and-continue, and no environment variable that turns the check off.

    WHY THIS RAISES WHERE ``warn_ephemeral_signing_key`` WARNS, since both
    guard key material and this repository has precedent both ways. That
    warning covers a process that generated a key IT WILL USE: the service
    still works, tokens still verify against its own JWKS, and the cost is
    confined to multi-replica deployments. This guards the absence of the only
    input that makes an approval more than a claim, and its failure mode is
    money moving on an unverified assertion. A control gating money fails at
    startup.

    The consequence is deliberate and worth naming: an operator who has not
    built enrolment yet gets a crash loop here, and closes it with an empty
    enrolment document, which starts and refuses every approval loudly
    (`postern_core.auth.device_keys`'s ``warn_no_enrolled_devices``). That is
    one line of configuration to say "no phone can approve yet", and no line
    of configuration anywhere says "approve without checking".
    """
    if not settings.device_keys_path:
        raise ValueError(
            "the confirm service cannot start without enrolled device keys: "
            "device_keys_path must be set (POSTERN_DEVICE_KEYS_PATH) to a JSON "
            "document of the public keys the operator enrolled for each customer. "
            "There is no unverified-signature mode on this service; see "
            "services/confirm/device_signature.py. An empty document "
            '({"customers": {}}) starts the service and refuses every approval.'
        )
    return FileDeviceKeyStore(Path(settings.device_keys_path))


def _refuse_process_local_sessions(settings: ConfirmSettings) -> None:
    """Refuse to start the device grant on per-process state, unless told to.

    Without ``POSTERN_REDIS_URL`` the refresh-family store and this service's
    ZT-7 store are per process: a refresh token from one replica is
    ``invalid_grant`` at another, and a recall at ``POST /scan`` writes the
    revoked ``jti`` into this process's memory, which ``services/api`` never
    reads. A service that cannot recall should not look ready, so this is a
    refusal at startup and not at ``POST /token``.

    ``POSTERN_ALLOW_PROCESS_LOCAL_SESSIONS`` is the development way out; with
    it the service starts, says so here, and every recall row records
    ``recall_local_only``. ``RuntimeError``, the type
    `postern_core.config.enforce_redis_requirement` chose for a
    deployment-wide contract not met.
    """
    if redis_url_from_env():
        return
    if settings.allow_process_local_sessions:
        logger.warning(
            "POSTERN_ALLOW_PROCESS_LOCAL_SESSIONS is set and POSTERN_REDIS_URL is not: "
            "refresh families and recalls live in this process only, and services/api "
            "never sees a recalled token. No multi-replica deployment may run this way."
        )
        return
    raise RuntimeError(
        "the confirm service cannot issue layer-1 sessions without shared state: "
        "POSTERN_REDIS_URL is not set, so refresh families and the ZT-7 list would be "
        "per process, a refresh token from one replica would be refused at another, and a "
        "recall at POST /scan would never reach services/api. Set POSTERN_REDIS_URL to "
        "the Redis services/api uses, or set POSTERN_ALLOW_PROCESS_LOCAL_SESSIONS for a "
        "single-process development stack."
    )


class _ConfirmApp(Starlette):
    """``Starlette`` with `TokenResponseHeaders` wrapped around the whole stack.

    Outside ``ServerErrorMiddleware``, which Starlette always installs
    outermost of the ``middleware=`` list, so the 500 it sends for an
    unhandled exception on ``/token`` carries ``Cache-Control: no-store`` and
    ``Pragma: no-cache`` too; no entry in that list can reach it. Amended
    1 October 2026.
    """

    def build_middleware_stack(self) -> ASGIApp:
        return TokenResponseHeaders(super().build_middleware_stack())


def create_confirm_app(
    settings: ConfirmSettings | None = None,
    *,
    assertion_verifier: AssertionVerifier | None = None,
    device_key_store: DeviceKeyStoreBase | None = None,
    network_enricher: NetworkEnricher | None | _FromEntryPoints = _FromEntryPoints.LOAD,
) -> Starlette:
    """Assemble the write-path ASGI app with device authorization and callback endpoints.

    Builds both read and write minters. The read key path is a controlled
    exception to the architecture's key-split rule — see ``ConfirmSettings``
    docstring.

    Also creates a database connection for the challenges table, wires the
    approval callback routes, and puts ``AppAssertionMiddleware`` in front of
    all of them.

    Args:
        settings: Service configuration. ``from_env()`` when omitted.
        assertion_verifier: Overrides the verifier built from ``settings``.
            The test seam, mirroring ``auth_override`` on
            ``services/api/server.py::build_server``: a test passes a
            ``JWTVerifier(public_key=...)`` over an ``RSAKeyPair.generate()``
            and needs no JWKS server. It is a keyword argument with no
            environment variable behind it, so no deployment can reach it by
            configuration.
        device_key_store: Overrides the store built from
            ``settings.device_keys_path``. The same kind of seam, for the same
            reason: a test that must approve something generates an Ed25519
            key pair and enrols the public half in an
            ``InMemoryDeviceKeyStore``, and one that must not passes
            ``no_enrolled_devices()``. Also keyword-only with no environment
            variable behind it, so it cannot become a deployment's answer to
            the guard below.
        network_enricher: Overrides the pairing network enricher loaded from
            the ``postern.pairing_network_enrichers`` entry-point group.
            ``None`` means no enricher, which is not the default: omitted, the
            installed distributions decide. Keyword-only with no environment
            variable behind it, like the two above.

    Raises:
        ValueError: if no verifier is given and the ``app_assertion_*``
            settings are incomplete, if no device key store is given and
            ``device_keys_path`` is unset, or if the document it names cannot
            be parsed. Refusing to build is the point in all three cases: it
            makes a confirm service that authenticates nobody, or that cannot
            verify an approval signature, unreachable by construction rather
            than by remembering to configure one. Also for every refusal
            ``check_session_token_settings`` makes.
        RuntimeError: if ``POSTERN_REDIS_URL`` is unset and
            ``allow_process_local_sessions`` is not (see
            ``_refuse_process_local_sessions``), after
            ``enforce_redis_requirement``'s own refusal.
        EnricherSeamViolation: if the installed enricher set is refused by
            ``load_network_enricher``: more than one, one that will not
            import, or one whose ``lookup`` is not async.
    """
    # FIRST, AND AHEAD OF THE AUTHENTICATION GUARD, which is a deliberate
    # exception to the ordering the next comment states. That order exists so
    # an operator missing both authentication and Redis hears about
    # authentication, and it is about two guards that read VALUES. This one
    # reads NAMES, and when it fires it is the explanation for whatever the
    # others are about to say: a typo in POSTERN_APP_ASSERTION_JWKS_URI makes
    # the assertion guard report an incomplete configuration, which sends the
    # operator to check a line they already wrote correctly. It costs one pass
    # over os.environ and builds nothing.
    enforce_known_environment(service="confirm")
    settings = settings or ConfirmSettings.from_env()
    verifier = assertion_verifier or _assertion_verifier(settings)
    # AFTER the assertion guard, so an operator missing both is told about
    # authentication first -- it is the outer control, and a service that
    # authenticates nobody has nothing to verify a signature for.
    keys = device_key_store or _device_key_store(settings)

    # THE SHARED-STATE CONTRACT, and until 2026-09-26 this service ignored it.
    # ``POSTERN_REQUIRE_REDIS=1`` means "refuse to run with per-replica state".
    # It was read in `services/api/main.py` and nowhere else, so an operator
    # who set it got the guarantee on the read path and none here -- where all
    # three of the stores built below degrade to per replica without a URL, and
    # the cost of each is what the message names.
    #
    # THIS IS A BREAKING CHANGE, said plainly because an operator will meet it
    # as a crash loop: a deployment running with the variable set and no URL
    # starts today and will not after this. That is the variable finally
    # meaning what it says, and the message is the only thing that will explain
    # it at 3am, which is why it names both variables, all three stores and
    # both ways out.
    #
    # PLACED AFTER THE TWO GUARDS ABOVE AND BEFORE ANY KEY IS BUILT. After,
    # because the priority those two established -- authentication first -- is
    # a decision a newer guard does not get to jump: an operator missing
    # authentication AND Redis is told about authentication.
    # `tests/test_require_redis_guard.py::TestTheWritePathStillFailsOnAuthenticationFirst`
    # pins that order. Before `build_write_minter`, because that generates an
    # RSA key, and a process that is about to refuse should not first spend one.
    enforce_redis_requirement(
        consequence=(
            "This service keeps three kinds of state in Redis: the ZT-7 "
            "revocation list, the device code store and the per-customer "
            "approval rate limit counters. Without POSTERN_REDIS_URL each is "
            "per replica, so a revocation cuts only the replica that happens "
            "to receive the next request, a device code spent on one replica "
            "stays redeemable on every other, and R replicas admit R times "
            "every per-customer approval ceiling. Set POSTERN_REDIS_URL to the "
            "same instance the read path uses, or unset POSTERN_REQUIRE_REDIS "
            "to accept per-replica state."
        )
    )
    # BESIDE THAT GUARD AND AFTER IT, so an operator who also set
    # POSTERN_REQUIRE_REDIS hears its message first. This one is the device
    # grant's own: without a shared Redis a session cannot be refreshed on
    # another replica or recalled at all.
    _refuse_process_local_sessions(settings)
    # The issuer and audience of every access token, refused here rather than
    # in `ConfirmSettings.__post_init__` so a settings object built by hand is
    # refused exactly where a deployment would be.
    check_session_token_settings(settings)

    # THE PAIRING NETWORK ENRICHER, LOADED ONCE AND BEFORE ANY KEY IS BUILT,
    # so a refused installed set lands at composition like every other
    # installed-distribution refusal in this repository, and a process about
    # to refuse does not first generate an RSA key.
    enricher = (
        load_network_enricher() if network_enricher is _FromEntryPoints.LOAD else network_enricher
    )

    # --- Write key / minter (existing path) ---
    _write_minter, write_key_source = build_write_minter(settings)

    # --- Session key / minter (the layer-1 access token) ---
    #
    # A THIRD KEY, which signs the access tokens `POST /token` issues and
    # nothing else, published at `/session/jwks.json` beside the write set and
    # never inside it. `services/confirm/session_token.py` says why it is not
    # the read key and not `InternalTokenMinter`.
    session_minter, session_key_source = build_session_minter(settings)

    # --- Read key / minter (device grant exception) ---
    #
    # THE ONE PROCESS IN THIS REPOSITORY THAT HOLDS TWO KEYS, and it is a
    # recorded exception rather than a leak: the device grant mints the
    # browser's read token in the same atomic step as the write one, so this
    # service needs both. `services/confirm/settings.py`'s module docstring is
    # where that is argued. Note what it is NOT: two calls to the same
    # one-key-in, one-source-out function, which is all
    # `choose_key_source` can do. There is still no object anywhere that
    # hands a process both.
    read_key_source = choose_key_source(
        role="READ (device grant)",
        kid=settings.read_key_kid,
        vault=settings.vault,
        vault_key_name=settings.vault_read_key_name,
        pem_path=settings.read_key_pem_path,
        pem_env_var="POSTERN_READ_KEY_PEM_PATH",
    )
    read_minter = InternalTokenMinter(issuer=settings.read_token_issuer, key_source=read_key_source)

    # --- Device code store ---
    #
    # The cap is passed in rather than read from the environment inside the
    # factory, so this service's settings stay the one place its
    # configuration is read. `postern_core.auth.device_codes`'s
    # ``DEFAULT_MAX_DEVICE_CODES`` holds the measurement behind the number
    # and ``DeviceCodeStoreFull`` holds why a full store refuses rather than
    # evicting.
    device_code_store = create_device_code_store(max_codes=settings.max_device_codes)

    # --- Refresh families (the layer-1 session) ---
    #
    # The same ``POSTERN_REDIS_URL`` as the device code store, so a refresh on
    # any replica finds the family an exchange on any other created.
    # `_refuse_process_local_sessions` above is why this cannot silently be
    # per process.
    refresh_session_store = create_refresh_session_store(max_sessions=settings.max_refresh_sessions)

    # --- ZT-7 revocation (shared with every `services/api` replica) ---
    #
    # THE SAME FACTORY BOTH SERVICES CALL, deliberately, so one
    # ``POSTERN_REDIS_URL`` points the read path, the write path and
    # `postern_core.auth.revoke_cli` at one key space. Pointing them at
    # different stores by construction is the failure this shape removes: an
    # operator would revoke, watch the reads stop, and never learn that the
    # approval path was reading an empty list.
    #
    # What this service asks of it is NOT what `services/api` asks --
    # `services/confirm/revocation.py` holds the whole argument and the three
    # call sites.
    revocation_store = create_revocation_store()

    # --- Per-customer approval counters (shared with every replica) ---
    #
    # THE FOURTH STORE BEHIND ONE ``POSTERN_REDIS_URL``, alongside the
    # revocation list above, the session store and the device code store, and
    # for the same reason the revocation store gives: pointing them at
    # different backends by construction is the failure the shared factory
    # shape removes. Unset, this one degrades to per-replica counters, which
    # for a per-customer ceiling means R replicas admit R times the configured
    # number -- `services/confirm/customer_rate_limit.py`'s
    # ``InMemoryCustomerRateLimitStore`` is where that is priced.
    customer_rate_limit_store = create_customer_rate_limit_store()

    # --- Database (for challenges table, §6.3 approval callback) ---
    db = Database(
        settings.database_url,
        connect_timeout_seconds=settings.database_connect_timeout_seconds,
        command_timeout_seconds=settings.database_command_timeout_seconds,
        pool_timeout_seconds=settings.database_pool_timeout_seconds,
        # 5 + 5 here against the read path's 5 + 10, both chosen on
        # 2026-09-26 where both were SQLAlchemy's by omission before.
        # `services/confirm/settings.py` carries why this service asks for
        # less and what raising it looks like.
        pool_size=settings.database_pool_size,
        max_overflow=settings.database_max_overflow,
        # THE RESERVE, narrower here than on the read path. It serves the two
        # COMPLETION writes in `services/confirm/audit.py` and deliberately not
        # `ApprovalAudit`'s entry row, which keeps the pool's refusal so that a
        # saturated replica stops before the backend write instead of being
        # carried past it on a connection that cannot see the
        # `approved -> executed` transition through.
        # `services/confirm/settings.py` carries the argument and
        # `tests/test_audit_reserve.py` measures both halves.
        audit_reserve_size=settings.database_audit_reserve_size,
    )

    # --- Assemble routes ---
    routes: list[Route] = (
        [jwks_route(write_key_source), session_jwks_route(session_key_source)]
        + device_auth_routes(store=device_code_store, settings=settings)
        + verify_page_routes()
        + callback_routes()
    )

    app = _ConfirmApp(
        routes=routes,
        middleware=[
            # AHEAD OF THE BODY LIMIT, AND THEREFORE AHEAD OF EVERYTHING.
            # A request this refuses must not first be drained: behind
            # `BodySizeLimit` every refusal would still cost a 64 KiB buffer,
            # which is the resource a flood is trying to spend. It answers
            # without ever calling ``receive``.
            #
            # It bounds the ARRIVAL RATE. The cap on what the device code
            # store will hold bounds the STANDING COST, and is passed to the
            # store above. `services/confirm/rate_limit.py` opens by saying
            # why neither substitutes for the other, and says plainly what
            # the pair does not achieve: they turn unbounded memory growth
            # into a bounded-memory denial of service, and stopping a
            # distributed flood before it arrives needs infrastructure that
            # is not in this repository.
            Middleware(
                RateLimit,
                trusted_proxy_hops=settings.trusted_proxy_hops,
                limits=limits_from_settings(
                    device_authorization=settings.rate_limit_device_authorization,
                    token=settings.rate_limit_token,
                    approve=settings.rate_limit_approve,
                    challenge_approve=settings.rate_limit_challenge_approve,
                    scan=settings.rate_limit_scan,
                    verify=settings.rate_limit_verify,
                    verify_qr=settings.rate_limit_verify_qr,
                    verify_state=settings.rate_limit_verify_state,
                    verify_js=settings.rate_limit_verify_js,
                    verify_css=settings.rate_limit_verify_css,
                    session_jwks=settings.rate_limit_session_jwks,
                ),
                fallback_limit=Limit(settings.rate_limit_default, RATE_LIMIT_WINDOW_SECONDS),
            ),
            # SECOND, AND STILL AHEAD OF AUTHENTICATION. Starlette builds the
            # stack in reverse (`starlette/applications.py::build_middleware_stack`),
            # so entry zero is the last one applied and therefore the first
            # one a request reaches -- the same reason
            # `services/api/main.py` lists `RequestDeadline` before
            # `HeaderBodyValidation`. This was entry zero until the rate
            # limit landed above it on 2026-09-24.
            #
            # In front of the assertion check on purpose: behind it, the body
            # would already be buffered by the time the signature was
            # verified, which is the cost this bound exists to avoid. In front
            # of it, an oversized body is refused before a JWKS fetch and
            # before a signature verification.
            #
            # This does NOT move the authentication boundary.
            # `AppAssertionMiddleware`'s docstring claims its placement means
            # "an unauthenticated request never reaches a handler, never opens
            # a database session and never touches the device code store", and
            # all three still hold: `BodySizeLimit` holds an int and a
            # `Receive`, reaches no store, no database and no handler, and can
            # only answer 413 or pass the request through to the middleware
            # below. `services/confirm/body_limit.py` carries the rest,
            # including why a request it refuses writes no `audit_log` row.
            Middleware(BodySizeLimit, max_body_bytes=settings.max_body_bytes),
            Middleware(
                AppAssertionMiddleware,
                verifier=verifier,
                max_lifetime_seconds=settings.app_assertion_max_lifetime_seconds,
            ),
            # LAST, AND THEREFORE INNERMOST -- the first middleware a request
            # meets is entry zero, so this is the last one before routing.
            # It has to be behind `AppAssertionMiddleware`, because the
            # customer it counts against is the verified `sub` and that does
            # not exist any further out.
            #
            # A SECOND LIMITER, NOT A RE-KEYING OF THE FIRST. The one at entry
            # zero counts per client address bucket, which is the wrong unit
            # for these three authenticated paths: sixty payment approvals a
            # minute from one customer is a signal and sixty from a bank's
            # egress address is a Tuesday. It stays where it is with its
            # numbers untouched, because a refusal from HERE has already cost
            # a JWKS fetch and a signature verification -- exactly the
            # resource entry zero exists to protect -- so the two are layered
            # and the outer one is the backstop.
            #
            # `services/confirm/customer_rate_limit.py` carries the rest: the
            # derivation of the ceilings, why the counters are shared
            # through `POSTERN_REDIS_URL` rather than held per replica, why an
            # unreachable counter refuses rather than admits, and why a
            # refusal writes a log line and no `audit_log` row.
            Middleware(
                CustomerRateLimit,
                store=customer_rate_limit_store,
                limits=customer_limits_from_settings(
                    approve=settings.customer_rate_limit_approve,
                    challenge_approve=settings.customer_rate_limit_challenge_approve,
                    scan=settings.customer_rate_limit_scan,
                ),
            ),
        ],
    )
    # Expose key sources on ``app.state`` for external consumers.
    app.state.postern_write_key_source = write_key_source
    app.state.postern_session_key_source = session_key_source
    app.state.postern_read_key_source = read_key_source
    # Expose minters and store for the device auth routes.
    app.state.read_minter = read_minter
    app.state.write_minter = _write_minter
    app.state.session_minter = session_minter
    app.state.device_code_store = device_code_store
    app.state.refresh_session_store = refresh_session_store
    # Expose database for the approval callback.
    app.state.postern_database = db
    # ZT-7: read by `services/confirm/revocation.py`'s `revocation_store` on
    # all four of this service's authenticated-or-minting paths. Same
    # attribute name as `services/api/main.py` uses, so one grep over both
    # services finds every place the control is wired.
    app.state.postern_revocation_store = revocation_store
    # Read by `services/confirm/device_signature.py`'s `device_key_store`, on
    # the one path that approves money movement. The ``postern_`` prefix
    # matches every other store this state dict carries, so a route table that
    # forgets one fails the same way the others do.
    app.state.postern_device_key_store = keys
    # Exposed for the same reason every other store on this dict is: a test
    # that must observe the counters, and an operator reading a route table,
    # both find it where the others are. Nothing reads it at request time --
    # `CustomerRateLimit` holds its own reference, because a middleware that
    # resolved its store per request could be made to run without one.
    app.state.postern_customer_rate_limit_store = customer_rate_limit_store
    app.state.settings = settings
    # Read by `services/confirm/device_auth.py` on a successful ``POST /scan``.
    # The semaphore bounds how many scans per process wait on the enricher at
    # once; that module's ``PAIRING_ENRICHMENT_SLOTS`` carries why eight.
    app.state.pairing_network_enricher = enricher
    app.state.pairing_network_slots = asyncio.Semaphore(PAIRING_ENRICHMENT_SLOTS)

    return app


def __getattr__(name: str) -> object:
    """PEP 562 lazy module attribute, mirroring ``services/api/main.py``'s own
    reasoning: ``import services.confirm.main`` (what every test does) stays
    free of building an app or generating a key, while ``uvicorn
    services.confirm.main:app`` still gets a real one at process start.
    """
    if name == "app":
        return create_confirm_app()
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

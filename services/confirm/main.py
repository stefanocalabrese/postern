"""Composition root for the write path and device authorization flow.

uvicorn targets ``services.confirm.main:app`` (see the ``confirm`` stage in
the Dockerfile).

Today this process does three things:
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

ZT-7 revocation cuts across all three: an operator who revokes a customer
stops their challenge approvals and their device-grant token mints as well as
their reads. Which scope reaches this service, and which two do not, is
`services/confirm/revocation.py`'s subject -- the summary is that the write
path can only be keyed on the customer, so **to stop it, name the customer**.

Everything except ``/.well-known/jwks.json``, ``/device_authorization`` and
``/token`` requires a verified banking-app assertion. ``services/confirm/auth.py``
holds that middleware, the reasoning for each public path, and the audience
requirement an operator owns. Until 2026-09-22 this app was built as
``Starlette(routes=routes)`` with no ``middleware=`` argument at all and
authenticated nobody on any route.

The device authorization endpoints are:
- ``POST /device_authorization`` — Generate device code + QR pairing data.
- ``POST /token`` with ``grant_type=device_code`` — Exchange device code for
  tokens (polling; returns error until mobile app approves).
- ``POST /approve`` — Mobile app approval callback.

The verification challenge endpoint is:
- ``POST /challenges/{challenge_id}/approve`` — Signed approval for a
  verification challenge (payments, card writes, etc.).

See ``services.confirm.device_auth`` for device auth endpoint implementations
and ``services.confirm.callback`` for the challenge approval handler.
"""

from fastmcp.server.auth.providers.jwt import JWTVerifier
from postern_core.auth.device_codes import create_device_code_store
from postern_core.auth.internal_jwt import InternalTokenMinter
from postern_core.auth.keys import GeneratedKeySource, warn_ephemeral_signing_key
from postern_core.auth.revocation import create_revocation_store
from postern_core.store.engine import Database
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.routing import Route

from services.confirm.auth import AppAssertionMiddleware, AssertionVerifier
from services.confirm.callback import callback_routes
from services.confirm.device_auth import device_auth_routes
from services.confirm.jwks import jwks_route
from services.confirm.minter import build_write_minter
from services.confirm.settings import ConfirmSettings


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


def create_confirm_app(
    settings: ConfirmSettings | None = None,
    *,
    assertion_verifier: AssertionVerifier | None = None,
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

    Raises:
        ValueError: if no verifier is given and the ``app_assertion_*``
            settings are incomplete. Refusing to build is the point: it makes
            an unauthenticated confirm service unreachable by construction
            rather than by remembering to configure one.
    """
    settings = settings or ConfirmSettings.from_env()
    verifier = assertion_verifier or _assertion_verifier(settings)

    # --- Write key / minter (existing path) ---
    _write_minter, write_key_source = build_write_minter(settings)

    # --- Read key / minter (device grant exception) ---
    from postern_core.auth.keys import FileKeySource

    if settings.read_key_pem_path is not None:
        from pathlib import Path

        read_key_source: FileKeySource | GeneratedKeySource = FileKeySource(
            Path(settings.read_key_pem_path), kid=settings.read_key_kid
        )
    else:
        read_key_source = GeneratedKeySource(kid=settings.read_key_kid)
        warn_ephemeral_signing_key(
            role="READ (device grant)",
            kid=settings.read_key_kid,
            pem_env_var="POSTERN_READ_KEY_PEM_PATH",
        )
    read_minter = InternalTokenMinter(issuer=settings.read_token_issuer, key_source=read_key_source)

    # --- Device code store ---
    device_code_store = create_device_code_store()

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

    # --- Database (for challenges table, §6.3 approval callback) ---
    db = Database(
        settings.database_url,
        connect_timeout_seconds=settings.database_connect_timeout_seconds,
        command_timeout_seconds=settings.database_command_timeout_seconds,
        pool_timeout_seconds=settings.database_pool_timeout_seconds,
    )

    # --- Assemble routes ---
    routes: list[Route] = (
        [jwks_route(write_key_source)]
        + device_auth_routes(
            store=device_code_store,
            settings=settings,
            read_minter=read_minter,
        )
        + callback_routes()
    )

    app = Starlette(
        routes=routes,
        middleware=[Middleware(AppAssertionMiddleware, verifier=verifier)],
    )
    # Expose key sources on ``app.state`` for external consumers.
    app.state.postern_write_key_source = write_key_source
    app.state.postern_read_key_source = read_key_source
    # Expose minters and store for the device auth routes.
    app.state.read_minter = read_minter
    app.state.write_minter = _write_minter
    app.state.device_code_store = device_code_store
    # Expose database for the approval callback.
    app.state.postern_database = db
    # ZT-7: read by `services/confirm/revocation.py`'s `revocation_store` on
    # all three of this service's authenticated-or-minting paths. Same
    # attribute name as `services/api/main.py` uses, so one grep over both
    # services finds every place the control is wired.
    app.state.postern_revocation_store = revocation_store
    app.state.settings = settings

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

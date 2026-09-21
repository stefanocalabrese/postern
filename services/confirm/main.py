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
   device codes, accept mobile app approvals, and exchange device codes for
   read + write tokens. The confirm service needs both read and write keys
   here because device code exchange mints both token types atomically — a
   controlled exception to the key-split architecture.
3. Handle verification challenge approvals (§6.3, §8.3): receive signed
   approvals from the mobile app, mark challenges approved in Postgres, and
   execute backend write endpoints server-side.

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

from postern_core.auth.device_codes import create_device_code_store
from postern_core.auth.internal_jwt import InternalTokenMinter
from postern_core.auth.keys import GeneratedKeySource, warn_ephemeral_signing_key
from postern_core.store.engine import Database
from starlette.applications import Starlette
from starlette.routing import Route

from services.confirm.callback import callback_routes
from services.confirm.device_auth import device_auth_routes
from services.confirm.jwks import jwks_route
from services.confirm.minter import build_write_minter
from services.confirm.settings import ConfirmSettings


def create_confirm_app(settings: ConfirmSettings | None = None) -> Starlette:
    """Assemble the write-path ASGI app with device authorization and callback endpoints.

    Builds both read and write minters (the confirm service needs both for
    device code exchange). The read key path is a controlled exception to the
    architecture's key-split rule — see ``ConfirmSettings`` docstring.

    Also creates a database connection for the challenges table and wires
    the approval callback routes.
    """
    settings = settings or ConfirmSettings.from_env()

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
            write_minter=_write_minter._minter,  # InternalTokenMinter behind the wrapper.
        )
        + callback_routes()
    )

    app = Starlette(routes=routes)
    # Expose key sources on ``app.state`` for external consumers.
    app.state.postern_write_key_source = write_key_source
    app.state.postern_read_key_source = read_key_source
    # Expose minters and store for the device auth routes.
    app.state.read_minter = read_minter
    app.state.write_minter = _write_minter
    app.state.device_code_store = device_code_store
    # Expose database for the approval callback.
    app.state.postern_database = db
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

"""Composition root for the write path. uvicorn targets
`services.confirm.main:app` (see the `confirm` stage in the Dockerfile).

This is NOT the approval callback -- that is Plan 5/6. Today this process
does exactly one thing: hold a write signing key and publish its public half
at `/.well-known/jwks.json`, under the write issuer, disjoint from the read
service's key and issuer. That is the minimum that makes "the tool handler
cannot reach a backend write endpoint" an infrastructure property: this
module never imports `services.api`, and nothing in `services.api` can reach
the key this module holds.
"""

from starlette.applications import Starlette

from services.confirm.jwks import jwks_route
from services.confirm.minter import build_write_minter
from services.confirm.settings import ConfirmSettings


def create_confirm_app(settings: ConfirmSettings | None = None) -> Starlette:
    """Assemble the write-path ASGI app: nothing but the write JWKS route."""
    settings = settings or ConfirmSettings.from_env()
    _minter, write_key_source = build_write_minter(settings)
    app = Starlette(routes=[jwks_route(write_key_source)])
    # The public half of the key `build_write_minter` signs with, exposed on
    # `app.state` the same way `services/api/main.py` exposes
    # `postern_read_key_source`: the only handle on the key outside the
    # minter it is buried in.
    app.state.postern_write_key_source = write_key_source
    return app


def __getattr__(name: str) -> object:
    """PEP 562 lazy module attribute, mirroring `services/api/main.py`'s own
    reasoning: `import services.confirm.main` (what every test does) stays
    free of building an app or generating a key, while `uvicorn
    services.confirm.main:app` still gets a real one at process start.
    """
    if name == "app":
        return create_confirm_app()
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

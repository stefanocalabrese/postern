"""The read JWKS endpoint.

This service publishes ONLY its own key. A combined key set holding both the
read and the write key voids the key split: a process holding just the read
key can claim the write issuer, sign with the read key, and a gateway that
resolves that issuer against a combined set accepts it. Measured 2026-09-16.
"""

from postern_core.auth.keys import KeySource
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

JWKS_PATH = "/.well-known/jwks.json"


def jwks_route(source: KeySource) -> Route:
    async def handler(_: Request) -> JSONResponse:
        return JSONResponse(source.public_jwks())

    return Route(JWKS_PATH, handler, methods=["GET"])

"""The read JWKS endpoint.

This service publishes ONLY its own key. A combined key set holding both the
read and the write key voids the key split: a process holding just the read
key can claim the write issuer, sign with the read key, and a gateway that
resolves that issuer against a combined set accepts it. Measured 2026-09-16.

`jwks_route` below is a deliberate duplicate of the one in
`services/confirm/jwks.py`, not an un-factored leftover. Both are the same
five-line builder over the same `KeySource` Protocol and the same
`JWKS_PATH`, and they stay that way:

1. A shared helper in `postern_core` would be LEGAL under the import
   contract, and that is the trap. `.importlinter` holds one contract,
   `api-not-confirm`, forbidding `services.api` from importing
   `services.confirm`; it says nothing about either service reaching
   `postern_core`, which both already import. `lint-imports` would pass a
   shared JWKS helper without a word, so a reader who treats that gate as
   the control guarding this split stops looking at the thing that is
   actually load-bearing.
2. A shared helper is also the natural home for a multi-key-source
   convenience: "take several `KeySource`s", "publish everything
   configured". The paragraph above is what that costs, measured 2026-09-16,
   not argued.
3. `postern_core` has no web-framework dependency at all. Its declared
   dependencies in `packages/postern-core/pyproject.toml` are `pydantic` and
   `joserfc`, and no file under `packages/postern-core/src/` imports
   Starlette. Hoisting this `Route` builder there would put Starlette into
   the library both deployables and every test import, to save about five
   lines.
4. Do not factor this file and `services/confirm/jwks.py` together.
5. If both need the same change, change both and keep them in step. That is
   the supported path, not a workaround around point 4. The realistic drift
   has a shape worth naming: one side gains a `Cache-Control` header or a
   caching layer and the other does not, or a `joserfc` export-shape change
   lands on one side only. Check for exactly that when touching either file.

`services/confirm/jwks.py` carries the matching comment.
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

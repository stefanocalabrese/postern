"""The write JWKS endpoint.

This service publishes ONLY its own key. A combined key set holding both the
read and the write key voids the key split: a process holding just the read
key can claim the write issuer, sign with the read key, and a gateway that
resolves that issuer against a combined set accepts it. Measured 2026-09-16
(see the plan's "Verified facts" section).

This module's `jwks_route` is a deliberate duplicate of `services/api/jwks.py`
(Task 3), not an un-factored leftover. Both define the same five-line
function over a `KeySource` Protocol and the same `JWKS_PATH`, and that is
intentional, for reasons stronger than "the import-linter contract forbids
`services.api -> services.confirm`":

1. A shared helper in `postern_core` would be LEGAL under that contract. The
   contract only forbids `services.api -> services.confirm`; it says nothing
   about either service reaching `postern_core`, which both already import.
   A reader who assumes `lint-imports` would catch a bad shared helper is
   trusting a control that does not apply here. And a shared JWKS module is
   exactly the kind of place a later "accept multiple key sources" or
   "publish all configured keys" convenience lands as a small, reasonable-
   looking commit -- Task 3's own measurement is what that costs: a combined
   key set voids the read/write split outright, because a process holding
   only the read key can claim the write issuer, sign with the read key,
   and a gateway resolving that issuer against a combined set accepts it.
2. `postern_core` has no web-framework dependency at all: its declared
   dependencies (`packages/postern-core/pyproject.toml`) are `pydantic` and
   `joserfc` only, and zero files under it import Starlette. Hoisting this
   `Route` builder there to save about five lines of body would put
   Starlette in the shared library every test and both deployables import.
   There is nowhere sensible to move this to, not just a rule against it.
3. Do not factor `services/api/jwks.py` and this file together.
4. If one needs a change, change both and keep them in step -- that is the
   supported path here, not a workaround around point 3. The realistic way
   these two drift is nameable: one side gains a `Cache-Control` header or a
   caching layer, or a `joserfc` `public_jwks()` export shape changes, and
   the other does not. Check for exactly that when touching either file.

`services/api/jwks.py` carries the matching comment.
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

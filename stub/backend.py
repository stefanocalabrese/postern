"""Stub of the bank's domain services for local development (handoff §8.7).

Runs only inside `docker compose`'s `backend-stub` service (see
`docker-compose.yml`), never inside the `api`/`confirm` images -- it is
excluded from both by `.dockerignore`. It returns the same shapes and the
same PAN/IBAN values as `tests/fixtures/backend_responses.py`, including a
full PAN and IBAN embedded in a transaction `description`: the point of
running the compose stack, unlike `pytest`, is to prove the running server
actually masks a full PAN and IBAN it received over real HTTP, not to prove
a route exists. If the server ever forwards one, the golden test and a
manual Inspector session both show it -- this stub is what puts a raw value
in front of that check outside the test suite too.
"""

import os

from fastmcp.server.auth.providers.jwt import RSAKeyPair
from joserfc import jwk
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse
from starlette.routing import Route

FULL_PAN = "4111111111114417"
FULL_IBAN = "ES9121000418450200051332"
COUNTERPARTY_IBAN = "DE89370400440532013000"

ACCOUNTS = {
    "accounts": [
        {"id": "acc_7f3a", "label": "Joint expenses", "iban": FULL_IBAN},
        {"id": "acc_9b21", "label": "Savings", "iban": "ES2221000418450200051119"},
    ]
}

BALANCE = {
    "account_id": "acc_7f3a",
    "amount": "1200.50",
    "currency": "EUR",
    "as_of": "2026-09-12T10:00:00Z",
}

TRANSACTIONS = {
    "transactions": [
        {
            "id": "txn_1",
            "account_id": "acc_7f3a",
            "booked_at": "2026-09-11T08:30:00Z",
            "amount": "-34.20",
            "currency": "EUR",
            "counterparty_name": "Acme Ltd",
            "counterparty_iban": COUNTERPARTY_IBAN,
            "description": f"Card {FULL_PAN} purchase, ref {COUNTERPARTY_IBAN}",
        }
    ]
}

CARDS = {"cards": [{"id": "crd_1", "label": "Debit", "pan": FULL_PAN, "status": "active"}]}


async def accounts(_request: Request) -> JSONResponse:
    return JSONResponse(ACCOUNTS)


async def balance(_request: Request) -> JSONResponse:
    return JSONResponse(BALANCE)


async def transactions(_request: Request) -> JSONResponse:
    return JSONResponse(TRANSACTIONS)


async def cards(_request: Request) -> JSONResponse:
    return JSONResponse(CARDS)


# --- Local dev-only identity-provider stand-in (Task 13 finding) -----------
#
# Not "the bank's domain services" -- this module's own docstring and scope
# -- this is a disposable RSA keypair and two routes standing in for the
# customer-facing OAuth/JWKS layer (handoff §7.1's "agent to MCP server"
# axis), a different concern from the domain data above with no real
# equivalent anywhere else in this repo.
#
# It exists because a genuinely auth-less `api` service can never complete a
# tool call: `services/api/server.py::token_customer_resolver` (the only
# customer resolver `create_app()` ever wires in production) always calls
# `fastmcp.server.dependencies.get_access_token()`, which returns `None` on
# every request when no auth provider is configured at all (there is no
# validated principal to attach to `request.scope["user"]` for it to read).
# `docker-compose.yml`'s `api` service therefore points `POSTERN_JWKS_URI`
# at this file's own `/.well-known/jwks.json`, so `services/api/server.py`'s
# `JWTVerifier` has something real (if throwaway) to check a bearer token
# against, and a token minted by `/mint-token` below verifies against it.
_KID = "local-dev"
_KEYPAIR = RSAKeyPair.generate()
_JWKS = {
    "keys": [
        jwk.import_key(
            _KEYPAIR.public_key,
            "RSA",
            parameters={"kid": _KID, "use": "sig", "alg": "RS256"},
        ).as_dict()
    ]
}


async def jwks(_request: Request) -> JSONResponse:
    return JSONResponse(_JWKS)


async def mint_token(request: Request) -> PlainTextResponse:
    """Dev-only: mint a bearer token this same process's JWKS can verify.

    `POSTERN_TOKEN_ISSUER`/`POSTERN_AUDIENCE` are read from this service's
    own environment (`docker-compose.yml` sets the same two values on both
    `backend-stub` and `api`) so the minted token and the `api` service's
    `JWTVerifier` always agree without hardcoding the same string twice.
    `sub` defaults to a `CustomerRef`-shaped value (`postern_core.identity`)
    already present in `ACCOUNTS` above.
    """
    subject = request.query_params.get("sub", "cust_7f3a")
    issuer = os.environ.get("POSTERN_TOKEN_ISSUER", "https://postern-local-dev.invalid")
    audience = os.environ.get("POSTERN_AUDIENCE", "postern")
    token = _KEYPAIR.create_token(subject=subject, issuer=issuer, audience=audience, kid=_KID)
    return PlainTextResponse(token)


app = Starlette(
    routes=[
        Route("/accounts", accounts),
        Route("/accounts/{account_id}/balance", balance),
        Route("/transactions", transactions),
        Route("/cards", cards),
        Route("/.well-known/jwks.json", jwks),
        Route("/mint-token", mint_token),
    ]
)

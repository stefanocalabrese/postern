"""Stub of the operator's domain services for local development (handoff §8.7).

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

All four domain routes scope their answer to the subject of the internal
token they receive (handoff §7.1's layer 2, `MCP server -> backend`) and
refuse a request that carries none. That is not ZT-2 itself: the domain
services that must enforce on `sub` belong to another team and are not in
this repo, and `docs/postern-zero-trust-plan.md` §3.2's A5 row still records
that enforcement as unverified there. It is what gives a cross-customer test
something that can fail here. Before it, every route took `_request: Request`
and never read it, so a caller naming `acc_4111111111114417` got `acc_7f3a`
back with no error: the stub did not merely skip the ownership check, it
could not tell which customer or which account was being asked about.
"""

import base64
import json
import os
from typing import Any

from fastmcp.server.auth.providers.jwt import RSAKeyPair
from joserfc import jwk
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse
from starlette.routing import Route

# Luhn-valid, corrected from 4111111111114417 by audit finding C-07 along
# with its mirror in `tests/fixtures/backend_responses.py`, which explains
# why an impossible card number could not stand in for a real one once a
# checksum entered the redaction path.
FULL_PAN = "4111111111111111"
FULL_IBAN = "ES9121000418450200051332"
COUNTERPARTY_IBAN = "DE89370400440532013000"

# Separator-grouped, lowercase and ordinal-split forms of the same two
# values, mirrored from `tests/fixtures/backend_responses.py` and held equal
# to it by `tests/test_stub_fixture_parity.py`. See that module for why each
# shape is here; the short version is that a card number typed with spaces
# is as much a leak as one typed without, and the compose stack has to put
# both in front of the running server, not just the contiguous one.
GROUPED_PAN = "4111 1111 1111 1111"
HYPHEN_PAN = "4111-1111-1111-1111"
DOTTED_PAN = "4111.1111.1111.1111"
NBSP_PAN = "4111 1111 1111 1111"
ORDINAL_PAN = "41111111º11111111"

GROUPED_IBAN = "ES91 2100 0418 4502 0005 1332"
HYPHEN_IBAN = "ES91-2100-0418-4502-0005-1332"
LOWERCASE_IBAN = "es9121000418450200051332"
ORDINAL_IBAN = "ES91210004184ª50200051332"

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

LEAKY_DESCRIPTION = (
    f"Card {FULL_PAN} purchase, ref {COUNTERPARTY_IBAN}"
    f" grouped {GROUPED_PAN} hyphen {HYPHEN_PAN} dotted {DOTTED_PAN}"
    f" nbsp {NBSP_PAN} ordinal {ORDINAL_PAN}"
    f" iban {GROUPED_IBAN} hyphen {HYPHEN_IBAN}"
    f" lower {LOWERCASE_IBAN} ordinal {ORDINAL_IBAN}"
)

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
            "description": LEAKY_DESCRIPTION,
        }
    ]
}

CARDS = {"cards": [{"id": "crd_1", "label": "Debit", "pan": FULL_PAN, "status": "active"}]}

# Fixture id -> owning customer. `cust_7f3a` and `cust_9b21` are the same two
# customers `tests/test_consent_enforcement.py` seeds consent for, so one
# customer ref means the same person in both files.
#
# A separate mapping rather than an `owner` key on each row, for two reasons.
# The response bodies stay byte-identical to
# `tests/fixtures/backend_responses.py`, which this module's docstring pins
# as its reason to exist; a per-row `owner` would have to be stripped on the
# way out, and a forgotten strip publishes a customer ref no accounts service
# would return, in a field the golden masking test (PAN- and IBAN-shaped
# values only) does not look for. And ownership stays single-sourced: `txn_1`
# has no entry of its own because it is booked on `acc_7f3a`, so
# `transactions()` resolves its owner through `account_id`, the way a core
# banking system resolves it. A second, independently editable owner on the
# transaction row could disagree with that row's own `account_id` -- a row
# owned by `cust_9b21` sitting on `cust_7f3a`'s account -- which is the exact
# cross-customer shape these routes exist to refuse.
OWNERS = {
    "acc_7f3a": "cust_7f3a",
    "acc_9b21": "cust_9b21",
    "crd_1": "cust_7f3a",
}

# Keyed by account id: a balance is reachable only through the account it
# belongs to, whose owner `OWNERS` already states, so there is no second
# place to declare who may read `BALANCE`. `acc_9b21` has no entry because
# the fixture set carries exactly one balance; `balance()` answers the same
# 404 for an owned account with no balance row as for an account owned by
# someone else.
BALANCES = {"acc_7f3a": BALANCE}

# `StubTokenMinter`'s entire output
# (`packages/postern-core/src/postern_core/facade/client.py`'s
# `StubTokenMinter.__call__` returns `f"stub.read.{customer.value}"`).
_STUB_MINTER_PREFIX = "stub.read."

# One constant body for every 404 from `balance()`, so "belongs to someone
# else" and "does not exist" are the same bytes as well as the same status.
_NO_SUCH_ACCOUNT = {"detail": "no such account"}


def _unauthorized() -> JSONResponse:
    """401 with an empty-handed body: no fixture value, no echo of the token.

    `WWW-Authenticate` is not decoration -- RFC 9110 §15.5.2 makes the header
    mandatory on a 401, and `postern_core.facade.client.BackendClient` turns
    any 4xx into a `BackendError` whose `detail` reaches the model, so the
    body says what is missing and nothing about who owns what.
    """
    return JSONResponse(
        {"detail": "missing or unreadable internal token"},
        status_code=401,
        headers={"WWW-Authenticate": "Bearer"},
    )


def _jwt_subject(credential: str) -> str | None:
    """`sub` out of a JWT's payload segment, WITHOUT verifying the signature.

    The missing verification is deliberate, not an oversight: this is a test
    double whose one job is subject scoping, not an authorization server. It
    holds no key it could check an internal token against (the keypair below
    belongs to the other hop, agent to MCP server), and it applies no issuer,
    audience or expiry policy. Enforcing on an unverified `sub` is what makes
    it a usable target for a cross-customer test, and what makes it unusable
    as anything else.

    A JWT carries unpadded base64url (RFC 7515 §2); Python's decoder wants
    the padding back.
    """
    segments = credential.split(".")
    if len(segments) != 3:
        return None
    payload = segments[1]
    try:
        claims: Any = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    except ValueError:
        # `binascii.Error`, `json.JSONDecodeError` and `UnicodeDecodeError`
        # are all `ValueError` subclasses, so a credential that merely looks
        # like a JWT fails closed into a 401 here rather than raising a 500
        # out of a route.
        return None
    if not isinstance(claims, dict):
        return None
    subject = claims.get("sub")
    return subject if isinstance(subject, str) and subject else None


def _subject(request: Request) -> str | None:
    """Customer ref the internal token names, or `None` if there isn't one.

    This reads hop 2 of handoff §7.1 (`MCP server -> backend`), never hop 1:
    the RS256 customer token `/mint-token` below issues is verified by the
    `api` service against this file's own JWKS and never reaches these
    routes. What reaches them is whatever
    `postern_core.facade.client.BackendClient.get_json` attaches, which in
    local dev is `StubTokenMinter`'s literal `stub.read.<customer>` and after
    Plan 3's Vault-backed `InternalTokenMinter` will be a real JWT. Both
    shapes are read here so that swap needs no edit on this side.

    Order matters: `stub.read.cust_7f3a` is itself three dot-separated
    segments, so a JWT-shaped test applied first would claim it and then fail
    to base64-decode `read` as a claims set. The literal prefix is checked
    first, which no JWT can collide with -- a JWT's first segment is a
    base64url-encoded JOSE header, and `stub` decodes to three bytes of
    non-JSON.

    Every failure returns `None`, which every route below turns into a 401.
    There is no header-absent path that serves data.
    """
    header = request.headers.get("authorization")
    if header is None:
        return None
    parts = header.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None
    credential = parts[1]
    if credential.startswith(_STUB_MINTER_PREFIX):
        return credential[len(_STUB_MINTER_PREFIX) :] or None
    return _jwt_subject(credential)


# `OWNERS.get(...)` returns `None` for any fixture row with no owner entry,
# and `subject` is a non-empty `str` by the time these comparisons run, so a
# row added to `ACCOUNTS`/`CARDS` without an `OWNERS` line is invisible to
# every customer rather than visible to all of them. Fail closed on data, the
# same way `_subject` fails closed on tokens.


async def accounts(request: Request) -> JSONResponse:
    subject = _subject(request)
    if subject is None:
        return _unauthorized()
    rows = [row for row in ACCOUNTS["accounts"] if OWNERS.get(row["id"]) == subject]
    return JSONResponse({"accounts": rows})


async def balance(request: Request) -> JSONResponse:
    subject = _subject(request)
    if subject is None:
        return _unauthorized()
    account_id = request.path_params["account_id"]
    # 404, not 403, when the account exists and belongs to another customer.
    # A 403 here would confirm that `acc_7f3a` is a real account while an
    # invented ref got a 404, which hands an attacker holding one valid
    # customer token a working account-enumeration oracle -- the disclosure
    # `docs/postern-zero-trust-plan.md` §3.2 calls A5, the confused deputy
    # ZT-2 exists to stop. Both cases take this one branch and return the
    # same body, so they are indistinguishable from outside. It reads like a
    # lost 403; it is the point.
    if OWNERS.get(account_id) != subject or account_id not in BALANCES:
        return JSONResponse(_NO_SUCH_ACCOUNT, status_code=404)
    return JSONResponse(BALANCES[account_id])


async def transactions(request: Request) -> JSONResponse:
    subject = _subject(request)
    if subject is None:
        return _unauthorized()
    # `facade/transactions.py` sends `account_id` and `days` as query
    # parameters; this stub ignores both, as it did before it could tell
    # customers apart. Narrowing by subject is what this route now does, and
    # it is enough for the cross-customer case: a customer who asks for
    # another customer's `account_id` gets their own rows, never that
    # account's.
    rows = [row for row in TRANSACTIONS["transactions"] if OWNERS.get(row["account_id"]) == subject]
    return JSONResponse({"transactions": rows})


async def cards(request: Request) -> JSONResponse:
    subject = _subject(request)
    if subject is None:
        return _unauthorized()
    rows = [row for row in CARDS["cards"] if OWNERS.get(row["id"]) == subject]
    return JSONResponse({"cards": rows})


# --- Local dev-only identity-provider stand-in (Task 13 finding) -----------
#
# Not "the operator's domain services" -- this module's own docstring and
# scope -- this is a disposable RSA keypair and two routes standing in for the
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
# `docker-compose.yml`'s `api` service pointed `POSTERN_JWKS_URI` at this
# file's own `/.well-known/jwks.json` until 2 October 2026. It now points at
# `confirm`'s `/session/jwks.json`, so `api` refuses a token minted by
# `/mint-token` below (another issuer, audience and key). What still reads
# this key set in that stack is `confirm`, as its app-assertion issuer
# (`POSTERN_APP_ASSERTION_JWKS_URI`), standing in for the banking app.
#
# Neither route carries the subject check the four domain routes above now
# carry, and that is not an omission: both belong to hop 1. A JWKS is a
# public document by construction, fetched by `JWTVerifier` before the `api`
# service holds any token at all, so gating it means no request is ever
# authenticated; `/mint-token` is where a local-dev token comes from, so
# requiring one to get one is circular.
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
    own environment. `docker-compose.yml` sets them on `backend-stub` only,
    to `https://postern-local-dev.invalid` and `postern`; `api` verifies
    `confirm`'s session tokens instead and refuses this token, and
    `confirm`'s app-assertion audience is `postern-confirm`, so in that
    stack neither service accepts what this route mints.
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

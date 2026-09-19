"""The backend stub must enforce on the internal token's subject (ZT-2).

`docs/postern-zero-trust-plan.md` §7 makes ZT-2 the critical path in those
words, and says why: "If the domain services do not enforce on the token
subject, nothing else in this plan matters." Those services are another
team's code and are not in this repo, so what this file tests is the local
test double, `stub/backend.py` -- the thing a cross-customer test has to run
against. Until it enforced,
nothing in local dev could fail such a test: all four domain routes took
`_request: Request`, never read it, and returned the same fixtures to
anybody, so the four `docs/verification/` records of runs against the compose
stack say nothing at all about authorization.

Every assertion here checks what is ABSENT from a body, not only the status
code. A test that asserts `status == 404` still passes when the body under
it carries the whole account, which is the leak the 404 exists to prevent.

Routes are driven over ASGI rather than in-process function calls so that
header parsing, path params and status codes are exercised the way
`postern_core.facade.client.BackendClient` exercises them: `_subject` reads
`request.headers`, and a header the framework never assembled is not a test
of a header.
"""

import base64
import json
from typing import Any

import httpx2
import pytest

from stub import backend as stub

# The two customers `tests/test_consent_enforcement.py` already uses, in the
# exact shape `StubTokenMinter` emits
# (`packages/postern-core/src/postern_core/facade/client.py:77`), which is
# what the stub receives in local dev.
OWNER = "Bearer stub.read.cust_7f3a"
OTHER = "Bearer stub.read.cust_9b21"

DOMAIN_ROUTES = ("/accounts", "/accounts/acc_7f3a/balance", "/transactions", "/cards")

# Every value a caller must not obtain without naming a subject that owns it.
FIXTURE_VALUES = (
    stub.FULL_PAN,
    stub.FULL_IBAN,
    stub.COUNTERPARTY_IBAN,
    "acc_7f3a",
    "acc_9b21",
    "crd_1",
    "txn_1",
    "1200.50",
)


async def get(
    path: str, *, authorization: str | None = None, params: dict[str, str] | None = None
) -> httpx2.Response:
    headers = {} if authorization is None else {"Authorization": authorization}
    async with httpx2.AsyncClient(
        transport=httpx2.ASGITransport(app=stub.app), base_url="http://backend-stub"
    ) as client:
        return await client.get(path, headers=headers, params=params)


def jwt(claims: dict[str, Any], *, signature: str = "c2ln") -> str:
    """A JWT-shaped credential: `{}` header, `claims` payload, `signature` as given.

    Unsigned by construction and never verified by the stub, which is the
    documented behaviour under test in
    `test_a_jwt_signature_is_deliberately_not_verified`. This stands in for
    Plan 3's Vault-backed `InternalTokenMinter` output, whose shape the stub
    already reads so the swap needs no change there.
    """
    payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
    return f"e30.{payload}.{signature}"


def ids(body: Any, key: str) -> list[str]:
    rows: list[dict[str, str]] = body[key]
    return [row["id"] for row in rows]


def assert_absent(response: httpx2.Response, *values: str) -> None:
    for value in values:
        assert value not in response.text, f"{value} reached a caller that does not own it"


# --- Cross-customer reads: the case A5/ZT-2 names -------------------------


async def test_a_customer_does_not_receive_another_customers_account() -> None:
    response = await get("/accounts", authorization=OTHER)
    assert response.status_code == 200
    assert ids(response.json(), "accounts") == ["acc_9b21"]
    assert_absent(response, "acc_7f3a", stub.FULL_IBAN)


async def test_a_customer_does_not_receive_another_customers_cards() -> None:
    response = await get("/cards", authorization=OTHER)
    assert response.status_code == 200
    assert response.json() == {"cards": []}
    assert_absent(response, "crd_1", stub.FULL_PAN)


async def test_a_customer_does_not_receive_another_customers_transactions() -> None:
    """`txn_1` carries a full PAN and two IBANs in its `description`, so this
    row leaking cross-customer leaks more than a payment date."""
    response = await get("/transactions", authorization=OTHER)
    assert response.status_code == 200
    assert response.json() == {"transactions": []}
    assert_absent(response, "txn_1", "acc_7f3a", stub.FULL_PAN, stub.COUNTERPARTY_IBAN)


async def test_naming_another_customers_account_id_does_not_widen_the_result() -> None:
    """`facade/transactions.py` sends `account_id` as a query parameter. The
    stub scopes on the token's subject and ignores the parameter, so asking
    for someone else's account returns the caller's own rows, never that
    account's."""
    response = await get(
        "/transactions", authorization=OTHER, params={"account_id": "acc_7f3a", "days": "30"}
    )
    assert response.status_code == 200
    assert response.json() == {"transactions": []}
    assert_absent(response, "txn_1", stub.FULL_PAN, stub.COUNTERPARTY_IBAN)


async def test_a_foreign_accounts_balance_is_404_and_the_body_holds_no_balance() -> None:
    response = await get("/accounts/acc_7f3a/balance", authorization=OTHER)
    assert response.status_code == 404
    assert_absent(response, "1200.50", "EUR", "acc_7f3a", "2026-09-12T10:00:00Z")


async def test_a_foreign_account_is_indistinguishable_from_one_that_does_not_exist() -> None:
    """The reason the route above answers 404 rather than 403.

    A 403 on `acc_7f3a` next to a 404 on an invented ref is an account
    enumeration oracle: it confirms which refs are real to anyone holding one
    valid customer token. Status AND body are compared, because a shared 404
    with two different `detail` strings is the same oracle with an extra
    step.
    """
    foreign = await get("/accounts/acc_7f3a/balance", authorization=OTHER)
    invented = await get("/accounts/acc_does_not_exist/balance", authorization=OTHER)
    assert foreign.status_code == 404
    assert (foreign.status_code, foreign.text) == (invented.status_code, invented.text)


async def test_an_unknown_subject_gets_empty_lists_rather_than_everything() -> None:
    """A subject that owns nothing must not degrade into the old behaviour of
    serving every fixture."""
    nobody = "Bearer stub.read.cust_nobody"
    accounts = await get("/accounts", authorization=nobody)
    cards = await get("/cards", authorization=nobody)
    transactions = await get("/transactions", authorization=nobody)
    balance = await get("/accounts/acc_7f3a/balance", authorization=nobody)
    assert accounts.json() == {"accounts": []}
    assert cards.json() == {"cards": []}
    assert transactions.json() == {"transactions": []}
    assert balance.status_code == 404
    for response in (accounts, cards, transactions, balance):
        assert_absent(response, *FIXTURE_VALUES)


# --- Fail closed: no token, no data ---------------------------------------


@pytest.mark.parametrize("path", DOMAIN_ROUTES)
async def test_a_request_with_no_authorization_header_gets_401_and_no_fixture(path: str) -> None:
    response = await get(path)
    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"
    assert_absent(response, *FIXTURE_VALUES)


@pytest.mark.parametrize(
    "header",
    [
        "",
        "Bearer",
        "Bearer ",
        "Basic c3R1Yi5yZWFkLmN1c3RfN2YzYQ==",
        "Token stub.read.cust_7f3a",
        "Bearer stub.read.cust_7f3a extra",
        "Bearer stub.read.",
        "Bearer not-a-token-at-all",
        "Bearer a.b",
        "Bearer a.b.c.d",
        "Bearer e30.@@@@.sig",
    ],
)
@pytest.mark.parametrize("path", DOMAIN_ROUTES)
async def test_a_malformed_authorization_header_gets_401_and_no_fixture(
    header: str, path: str
) -> None:
    response = await get(path, authorization=header)
    assert response.status_code == 401
    assert_absent(response, *FIXTURE_VALUES)


@pytest.mark.parametrize(
    "claims",
    [
        {},
        {"sub": ""},
        {"sub": 7},
        {"sub": None},
        {"subject": "cust_7f3a"},
    ],
)
@pytest.mark.parametrize("path", DOMAIN_ROUTES)
async def test_a_jwt_without_a_usable_subject_gets_401_and_no_fixture(
    claims: dict[str, Any], path: str
) -> None:
    response = await get(path, authorization=f"Bearer {jwt(claims)}")
    assert response.status_code == 401
    assert_absent(response, *FIXTURE_VALUES)


async def test_a_jwt_payload_that_is_not_an_object_gets_401() -> None:
    payload = base64.urlsafe_b64encode(b"[1, 2]").decode().rstrip("=")
    response = await get("/accounts", authorization=f"Bearer e30.{payload}.sig")
    assert response.status_code == 401
    assert_absent(response, *FIXTURE_VALUES)


# --- Both token shapes: `stub.read.` today, a JWT after Plan 3 ------------


async def test_a_jwt_subject_is_scoped_the_same_way_as_a_stub_token() -> None:
    response = await get("/accounts", authorization=f"Bearer {jwt({'sub': 'cust_9b21'})}")
    assert response.status_code == 200
    assert ids(response.json(), "accounts") == ["acc_9b21"]
    assert_absent(response, "acc_7f3a", stub.FULL_IBAN)


async def test_a_jwt_signature_is_deliberately_not_verified() -> None:
    """Pins a documented choice, not an accident.

    `stub/backend.py::_jwt_subject` reads `sub` without checking the
    signature because the stub is a test double for subject scoping, holds no
    key for the backend hop, and applies no issuer/audience/expiry policy.
    Anyone adding verification will fail this test, which is where the
    reasoning is written down.
    """
    forged = jwt({"sub": "cust_7f3a"}, signature="bm90LWEtc2lnbmF0dXJl")
    response = await get("/accounts", authorization=f"Bearer {forged}")
    assert response.status_code == 200
    assert ids(response.json(), "accounts") == ["acc_7f3a"]


async def test_a_stub_token_is_not_mistaken_for_a_jwt() -> None:
    """`stub.read.cust_9b21` is itself three dot-separated segments, so a
    JWT-shaped test applied before the prefix test would claim it, fail to
    decode `read` as a claims set, and 401 every local-dev request."""
    assert len("stub.read.cust_9b21".split(".")) == 3
    response = await get("/accounts", authorization=OTHER)
    assert response.status_code == 200
    assert ids(response.json(), "accounts") == ["acc_9b21"]


async def test_the_bearer_scheme_is_matched_case_insensitively() -> None:
    """RFC 9110 §11.1 makes the scheme case-insensitive; `BackendClient`
    sends `Bearer`, but rejecting `bearer` would be a parser bug, not a
    control."""
    response = await get("/accounts", authorization="bearer stub.read.cust_9b21")
    assert response.status_code == 200
    assert ids(response.json(), "accounts") == ["acc_9b21"]


# --- The happy path, or this file only proves the stub can be broken ------


async def test_the_owning_customer_still_reads_its_own_accounts() -> None:
    response = await get("/accounts", authorization=OWNER)
    assert response.status_code == 200
    assert response.json() == {
        "accounts": [{"id": "acc_7f3a", "label": "Joint expenses", "iban": stub.FULL_IBAN}]
    }


async def test_the_owning_customer_still_reads_its_own_balance() -> None:
    response = await get("/accounts/acc_7f3a/balance", authorization=OWNER)
    assert response.status_code == 200
    assert response.json() == stub.BALANCE


async def test_the_owning_customer_still_reads_its_own_cards() -> None:
    response = await get("/cards", authorization=OWNER)
    assert response.status_code == 200
    assert response.json() == stub.CARDS


async def test_the_owning_customer_still_reads_its_own_transactions() -> None:
    """Still carrying the raw PAN and IBAN the compose stack exists to prove
    `services/api` masks: scoping decides WHO gets the row, masking decides
    what the row looks like by the time a model sees it. This stub must keep
    handing the owner an unmasked value."""
    response = await get("/transactions", authorization=OWNER)
    assert response.status_code == 200
    assert response.json() == stub.TRANSACTIONS
    assert stub.FULL_PAN in response.text


async def test_the_second_customer_reads_its_own_account() -> None:
    response = await get("/accounts", authorization=OTHER)
    assert response.status_code == 200
    assert response.json()["accounts"] == [
        {"id": "acc_9b21", "label": "Savings", "iban": "ES2221000418450200051119"}
    ]


# --- Drift guard on the fixtures ------------------------------------------


def test_every_fixture_row_has_an_owner() -> None:
    """A row added to `ACCOUNTS`/`CARDS` with no `OWNERS` entry is invisible
    to everyone, which fails closed but silently: the row exists, no customer
    can read it, and the tests above still pass. This is what makes that
    visible in the diff instead of at the next manual stack run.
    """
    owned = set(stub.OWNERS)
    assert {row["id"] for row in stub.ACCOUNTS["accounts"]} <= owned
    assert {row["id"] for row in stub.CARDS["cards"]} <= owned
    assert {row["account_id"] for row in stub.TRANSACTIONS["transactions"]} <= owned
    assert set(stub.BALANCES) <= owned

"""`payments.create_payment` and `get_payment_status`: a foreign ref reads as an unknown one.

`create_payment` reads the payer account and the payee through the read facade
before it writes a challenge, and maps a backend refusal of either ref to a
fixed sentence (`account not found`, `payee not found`). The contract is a 404
for a ref that belongs to another customer exactly as for one that does not
(CLAUDE.md operator item 1), and the read tools also map a 403 so a backend
that breaks the contract does not hand the model an existence oracle (A5,
`services/api/tools/not_found.py`). These tests pin the same property here, per
ref kind, on bytes and on the audit rows:

* a 404 and a 403 for a ref give the same fixed sentence;
* every other status and a failure to reach the backend stay masked;
* a foreign ref and an unknown ref are byte-identical in the response and in
  every `audit_log` column that is not volatile or the caller's own argument,
  against the real stub and against a backend that answers 403 for the foreign
  one;
* none of it creates a challenge row.
"""

from collections.abc import Callable

import httpx2
import pytest
from fastmcp import FastMCP
from fastmcp.server.auth.providers.jwt import JWTVerifier, RSAKeyPair
from postern_core.payments import CREATE_PAYMENT_TOOL, PAYMENT_STATUS_TOOL
from postern_core.store.engine import Database
from postern_core.store.models import AuditEntry
from sqlalchemy import select

from services.api.main import create_app
from services.api.settings import Settings
from services.api.tools.payments import (
    ACCOUNT_NOT_FOUND,
    CHALLENGE_NOT_FOUND,
    PAYEE_NOT_FOUND,
)
from stub import backend as stub
from tests.fixtures.payments_http import (
    ARGS,
    AUDIENCE,
    ISSUER,
    OTHER,
    OWNER,
    grant,
    insert_row,
    post_tool,
    result_of,
    rows,
    token_for,
)

pytest_plugins = ["tests.fixtures.payments_http"]

SENTINEL = "zzsentinel_backend_body_8841"
#: Refs the stub knows: `acc_9b21` and `pay_ll02` belong to `OTHER`.
FOREIGN_ACCOUNT = "acc_9b21"
FOREIGN_PAYEE = "pay_ll02"
UNKNOWN_ACCOUNT = "acc_neverexisted"
UNKNOWN_PAYEE = "pay_neverexisted"

#: Columns a second identical call may legitimately differ in: the row's own
#: id and clocks, the measured duration, the correlation id, and the caller's own arguments.
_VOLATILE = {"id", "at", "reaching_at", "call_id", "arguments", "duration_ms"}

Handler = Callable[[httpx2.Request], httpx2.Response]

_KINDS = {
    "account": ("from_account_ref", ACCOUNT_NOT_FOUND, "/accounts/"),
    "payee": ("payee_ref", PAYEE_NOT_FOUND, "/payees/"),
}


def _failing(kind: str, status: int) -> Handler:
    """Healthy for the other ref, `status` for the one under test."""
    _, _, prefix = _KINDS[kind]

    def handler(request: httpx2.Request) -> httpx2.Response:
        if request.url.path.startswith(prefix):
            return httpx2.Response(status, json={"detail": SENTINEL})
        if request.url.path.startswith("/accounts/"):
            return httpx2.Response(200, json=stub.BALANCE)
        return httpx2.Response(200, json=stub.PAYEE)

    return handler


def _unreachable(kind: str) -> Handler:
    healthy = _failing(kind, 200)
    _, _, prefix = _KINDS[kind]

    def handler(request: httpx2.Request) -> httpx2.Response:
        if request.url.path.startswith(prefix):
            raise httpx2.ConnectError(f"{SENTINEL} host:6379")
        return healthy(request)

    return handler


def _foreign_is_403(kind: str) -> Handler:
    """A non-conforming backend: 403 for the foreign ref, 404 for any other."""
    _, _, prefix = _KINDS[kind]
    foreign = FOREIGN_ACCOUNT if kind == "account" else FOREIGN_PAYEE
    healthy = _failing(kind, 200)

    def handler(request: httpx2.Request) -> httpx2.Response:
        if request.url.path.startswith(prefix):
            status = 403 if foreign in request.url.path else 404
            return httpx2.Response(status, json={"detail": SENTINEL})
        return healthy(request)

    return handler


async def _call(
    pg_url: str,
    key_pair: RSAKeyPair,
    transport: httpx2.AsyncBaseTransport,
    customer: str,
    tool: str,
    arguments: dict[str, str],
) -> httpx2.Response:
    settings = Settings(
        backend_base_url="http://backend-stub",
        database_url=pg_url,
        customer_jwks_uri=None,
        customer_token_issuer=None,
        payments_enabled=True,
    )
    verifier = JWTVerifier(public_key=key_pair.public_key, issuer=ISSUER, audience=AUDIENCE)
    app = create_app(settings, transport=transport, auth_override=verifier)
    return await post_tool(app, token_for(key_pair, customer), tool, arguments)


def _text(response: httpx2.Response) -> str:
    result = result_of(response)
    assert result["isError"] is True, response.text
    (block,) = result["content"]
    return str(block["text"])


async def _audit(database: Database, customer: str) -> list[dict[str, object]]:
    """This customer's audit rows in order, volatile columns stripped."""
    async with database.sessionmaker() as session:
        found = await session.execute(
            select(AuditEntry).where(AuditEntry.customer_ref == customer).order_by(AuditEntry.id)
        )
        entries = list(found.scalars().all())
    keep = [name for name in AuditEntry.__table__.columns.keys() if name not in _VOLATILE]
    return [{name: getattr(entry, name) for name in keep} for entry in entries]


def _assert_two_calls_wrote_the_same_rows(audit: list[dict[str, object]]) -> None:
    """Each call wrote the same number of rows, and the two halves are equal."""
    assert audit and len(audit) % 2 == 0, audit
    half = len(audit) // 2
    assert audit[:half] == audit[half:]


# -- one ref kind at a time: 404 and 403 are one sentence ---------------------------


@pytest.mark.parametrize("status", [404, 403])
@pytest.mark.parametrize("kind", ["account", "payee"])
async def test_a_backend_404_or_403_for_a_ref_is_that_refs_fixed_sentence(
    pg_url: str,
    payments_key_pair: RSAKeyPair,
    payments_produced: Database,
    audit_server: FastMCP,
    kind: str,
    status: int,
) -> None:
    await grant(payments_produced, OWNER, "payments")

    response = await _call(
        pg_url,
        payments_key_pair,
        httpx2.MockTransport(_failing(kind, status)),
        OWNER,
        CREATE_PAYMENT_TOOL,
        ARGS,
    )

    assert _text(response) == _KINDS[kind][1]
    assert SENTINEL not in response.text
    assert await rows(payments_produced) == []


@pytest.mark.parametrize("status", [400, 401, 500, 503])
@pytest.mark.parametrize("kind", ["account", "payee"])
async def test_every_other_backend_status_stays_masked(
    pg_url: str,
    payments_key_pair: RSAKeyPair,
    payments_produced: Database,
    audit_server: FastMCP,
    kind: str,
    status: int,
) -> None:
    await grant(payments_produced, OWNER, "payments")

    response = await _call(
        pg_url,
        payments_key_pair,
        httpx2.MockTransport(_failing(kind, status)),
        OWNER,
        CREATE_PAYMENT_TOOL,
        ARGS,
    )

    assert _text(response) == f"Error calling tool '{CREATE_PAYMENT_TOOL}'"
    assert SENTINEL not in response.text
    assert await rows(payments_produced) == []


@pytest.mark.parametrize("kind", ["account", "payee"])
async def test_a_transport_failure_stays_masked(
    pg_url: str,
    payments_key_pair: RSAKeyPair,
    payments_produced: Database,
    audit_server: FastMCP,
    kind: str,
) -> None:
    await grant(payments_produced, OWNER, "payments")

    response = await _call(
        pg_url,
        payments_key_pair,
        httpx2.MockTransport(_unreachable(kind)),
        OWNER,
        CREATE_PAYMENT_TOOL,
        ARGS,
    )

    assert _text(response) == f"Error calling tool '{CREATE_PAYMENT_TOOL}'"
    assert SENTINEL not in response.text
    assert await rows(payments_produced) == []


# -- foreign against unknown: bytes and audit rows ----------------------------------


@pytest.mark.parametrize("kind", ["account", "payee"])
async def test_against_the_real_stub_a_foreign_ref_and_an_unknown_ref_are_indistinguishable(
    pg_url: str,
    payments_key_pair: RSAKeyPair,
    payments_produced: Database,
    audit_server: FastMCP,
    kind: str,
) -> None:
    field, sentence, _ = _KINDS[kind]
    foreign = FOREIGN_ACCOUNT if kind == "account" else FOREIGN_PAYEE
    unknown = UNKNOWN_ACCOUNT if kind == "account" else UNKNOWN_PAYEE
    await grant(payments_produced, OWNER, "payments")
    transport = httpx2.ASGITransport(app=stub.app)

    first = await _call(
        pg_url, payments_key_pair, transport, OWNER, CREATE_PAYMENT_TOOL, {**ARGS, field: foreign}
    )
    second = await _call(
        pg_url, payments_key_pair, transport, OWNER, CREATE_PAYMENT_TOOL, {**ARGS, field: unknown}
    )

    assert _text(first) == sentence
    assert first.content == second.content
    assert first.status_code == second.status_code
    _assert_two_calls_wrote_the_same_rows(await _audit(payments_produced, OWNER))
    assert await rows(payments_produced) == []


@pytest.mark.parametrize("kind", ["account", "payee"])
async def test_a_backend_answering_403_for_a_foreign_ref_is_indistinguishable_from_404(
    pg_url: str,
    payments_key_pair: RSAKeyPair,
    payments_produced: Database,
    audit_server: FastMCP,
    kind: str,
) -> None:
    field, sentence, _ = _KINDS[kind]
    foreign = FOREIGN_ACCOUNT if kind == "account" else FOREIGN_PAYEE
    unknown = UNKNOWN_ACCOUNT if kind == "account" else UNKNOWN_PAYEE
    await grant(payments_produced, OWNER, "payments")
    transport = httpx2.MockTransport(_foreign_is_403(kind))

    first = await _call(
        pg_url, payments_key_pair, transport, OWNER, CREATE_PAYMENT_TOOL, {**ARGS, field: foreign}
    )
    second = await _call(
        pg_url, payments_key_pair, transport, OWNER, CREATE_PAYMENT_TOOL, {**ARGS, field: unknown}
    )

    assert _text(first) == sentence
    assert first.content == second.content
    assert first.status_code == second.status_code
    _assert_two_calls_wrote_the_same_rows(await _audit(payments_produced, OWNER))
    assert await rows(payments_produced) == []


# -- the status tool: another customer's challenge against an invented one ----------


async def test_a_foreign_challenge_id_and_an_unknown_one_are_indistinguishable(
    pg_url: str,
    payments_key_pair: RSAKeyPair,
    payments_produced: Database,
    audit_server: FastMCP,
) -> None:
    await grant(payments_produced, OWNER, "payments")
    foreign = await insert_row(payments_produced, customer_ref=OTHER, tool_name=CREATE_PAYMENT_TOOL)
    transport = httpx2.ASGITransport(app=stub.app)

    first = await _call(
        pg_url, payments_key_pair, transport, OWNER, PAYMENT_STATUS_TOOL, {"challenge_id": foreign}
    )
    second = await _call(
        pg_url,
        payments_key_pair,
        transport,
        OWNER,
        PAYMENT_STATUS_TOOL,
        {"challenge_id": "0" * 32},
    )

    assert _text(first) == CHALLENGE_NOT_FOUND
    assert first.content == second.content
    assert first.status_code == second.status_code
    _assert_two_calls_wrote_the_same_rows(await _audit(payments_produced, OWNER))

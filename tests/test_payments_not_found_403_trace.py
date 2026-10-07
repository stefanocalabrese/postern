"""`payments.create_payment` leaves the same 403 trace as the read tools.

`create_payment` maps a backend 403 on the payer account or the payee to
`account not found` / `payee not found`, byte for byte a 404's. A minter whose
tokens the backend rejects on every call would therefore look like customers
mistyping refs on the payment tools too, so a 403 (and only a 403) logs the
fixed warning of `services/api/tools/not_found.py` with `tool=payments.create_payment`,
at most once per 60 seconds for that tool name. No ref, argument or body is in it.
"""

import logging

import httpx2
import pytest
from fastmcp import FastMCP
from fastmcp.exceptions import ToolError
from fastmcp.server.auth.providers.jwt import RSAKeyPair
from postern_core.facade.client import BackendError
from postern_core.payments import CREATE_PAYMENT_TOOL
from postern_core.store.engine import Database

from services.api.tools import not_found
from services.api.tools.not_found import not_found_is_a_fixed_refusal
from tests.fixtures.payments_http import ARGS, OWNER, grant, rows
from tests.test_payments_not_found import (  # noqa: F401  (fixtures)
    _KINDS,
    FOREIGN_ACCOUNT,
    FOREIGN_PAYEE,
    SENTINEL,
    _call,
    _failing,
    _text,
    _unreachable,
)

pytest_plugins = ["tests.fixtures.payments_http"]

LOGGER = "services.api.tools.not_found"
MARKER = "backend answered 403 on a caller-chosen ref"


class _Clock:
    def __init__(self) -> None:
        self.now = 5000.0

    def __call__(self) -> float:
        return self.now


@pytest.fixture(autouse=True)
def clock(monkeypatch: pytest.MonkeyPatch) -> _Clock:
    fake = _Clock()
    monkeypatch.setattr(not_found, "_clock", fake)
    monkeypatch.setattr(not_found, "_last_warned_at", {})
    return fake


def _warnings(caplog: pytest.LogCaptureFixture) -> list[logging.LogRecord]:
    return [r for r in caplog.records if r.name == LOGGER]


async def _create(
    pg_url: str, key_pair: RSAKeyPair, transport: httpx2.AsyncBaseTransport
) -> httpx2.Response:
    return await _call(pg_url, key_pair, transport, OWNER, CREATE_PAYMENT_TOOL, ARGS)


@pytest.mark.parametrize("kind", ["account", "payee"])
async def test_a_403_on_a_payment_ref_logs_one_warning_naming_the_tool(
    pg_url: str,
    payments_key_pair: RSAKeyPair,
    payments_produced: Database,
    audit_server: FastMCP,
    caplog: pytest.LogCaptureFixture,
    kind: str,
) -> None:
    await grant(payments_produced, OWNER, "payments")
    caplog.set_level(logging.DEBUG)

    response = await _create(pg_url, payments_key_pair, httpx2.MockTransport(_failing(kind, 403)))

    assert _text(response) == _KINDS[kind][1], "the model-facing sentence is unchanged"
    records = _warnings(caplog)
    assert len(records) == 1
    assert records[0].levelno == logging.WARNING
    text = records[0].getMessage()
    assert MARKER in text
    assert f"tool={CREATE_PAYMENT_TOOL}" in text
    assert "audience and scope" in text
    for forbidden in (
        ARGS["from_account_ref"],
        ARGS["payee_ref"],
        ARGS["amount"],
        SENTINEL,
        OWNER,
        FOREIGN_ACCOUNT,
        FOREIGN_PAYEE,
    ):
        assert forbidden not in text
    assert SENTINEL not in caplog.text
    assert await rows(payments_produced) == [], "no challenge row"


@pytest.mark.parametrize("kind", ["account", "payee"])
async def test_a_403_gives_the_same_bytes_as_a_404(
    pg_url: str,
    payments_key_pair: RSAKeyPair,
    payments_produced: Database,
    audit_server: FastMCP,
    caplog: pytest.LogCaptureFixture,
    kind: str,
) -> None:
    await grant(payments_produced, OWNER, "payments")
    caplog.set_level(logging.DEBUG)
    not_found_404 = await _create(
        pg_url, payments_key_pair, httpx2.MockTransport(_failing(kind, 404))
    )
    assert _warnings(caplog) == []
    forbidden = await _create(pg_url, payments_key_pair, httpx2.MockTransport(_failing(kind, 403)))
    assert forbidden.content == not_found_404.content
    assert len(_warnings(caplog)) == 1


@pytest.mark.parametrize("kind", ["account", "payee"])
async def test_a_404_logs_nothing(
    pg_url: str,
    payments_key_pair: RSAKeyPair,
    payments_produced: Database,
    audit_server: FastMCP,
    caplog: pytest.LogCaptureFixture,
    kind: str,
) -> None:
    await grant(payments_produced, OWNER, "payments")
    caplog.set_level(logging.DEBUG)
    await _create(pg_url, payments_key_pair, httpx2.MockTransport(_failing(kind, 404)))
    assert _warnings(caplog) == []


@pytest.mark.parametrize("status", [400, 401, 500, 503])
@pytest.mark.parametrize("kind", ["account", "payee"])
async def test_every_other_status_logs_nothing_here(
    pg_url: str,
    payments_key_pair: RSAKeyPair,
    payments_produced: Database,
    audit_server: FastMCP,
    caplog: pytest.LogCaptureFixture,
    kind: str,
    status: int,
) -> None:
    await grant(payments_produced, OWNER, "payments")
    caplog.set_level(logging.DEBUG)
    await _create(pg_url, payments_key_pair, httpx2.MockTransport(_failing(kind, status)))
    assert _warnings(caplog) == []


@pytest.mark.parametrize("kind", ["account", "payee"])
async def test_a_transport_failure_logs_nothing_here(
    pg_url: str,
    payments_key_pair: RSAKeyPair,
    payments_produced: Database,
    audit_server: FastMCP,
    caplog: pytest.LogCaptureFixture,
    kind: str,
) -> None:
    await grant(payments_produced, OWNER, "payments")
    caplog.set_level(logging.DEBUG)
    await _create(pg_url, payments_key_pair, httpx2.MockTransport(_unreachable(kind)))
    assert _warnings(caplog) == []


async def test_the_payment_tool_is_rate_limited_on_its_own_window(
    pg_url: str,
    payments_key_pair: RSAKeyPair,
    payments_produced: Database,
    audit_server: FastMCP,
    caplog: pytest.LogCaptureFixture,
    clock: _Clock,
) -> None:
    await grant(payments_produced, OWNER, "payments")
    caplog.set_level(logging.DEBUG)
    account_403 = httpx2.MockTransport(_failing("account", 403))
    payee_403 = httpx2.MockTransport(_failing("payee", 403))

    await _create(pg_url, payments_key_pair, account_403)
    await _create(pg_url, payments_key_pair, payee_403)
    assert len(_warnings(caplog)) == 1, "same tool, same window, whichever ref"

    # A 403 on a read tool is another tool name and still logs.
    with pytest.raises(ToolError):
        async with not_found_is_a_fixed_refusal("accounts.get_balance"):
            raise BackendError(403, "x")
    texts = [r.getMessage() for r in _warnings(caplog)]
    assert len(texts) == 2
    assert "tool=accounts.get_balance" in texts[1]

    clock.now += 60.1
    await _create(pg_url, payments_key_pair, account_403)
    texts = [r.getMessage() for r in _warnings(caplog)]
    assert len(texts) == 3
    assert f"tool={CREATE_PAYMENT_TOOL}" in texts[2]


async def test_a_payment_403_does_not_hide_a_read_tool_403_in_the_same_minute(
    pg_url: str,
    payments_key_pair: RSAKeyPair,
    payments_produced: Database,
    audit_server: FastMCP,
    caplog: pytest.LogCaptureFixture,
) -> None:
    await grant(payments_produced, OWNER, "payments")
    caplog.set_level(logging.DEBUG)
    await _create(pg_url, payments_key_pair, httpx2.MockTransport(_failing("account", 403)))
    with pytest.raises(ToolError):
        async with not_found_is_a_fixed_refusal("transactions.list"):
            raise BackendError(403, "x")
    assert len(_warnings(caplog)) == 2

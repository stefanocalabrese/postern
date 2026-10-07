"""Every JSON body the two services parse is read with ``loads_finite``.

``postern_core.json_strict`` is unit-tested in ``tests/test_json_strict.py``.
This file is the other half: that each call site USES it, through the real
assembled app, so replacing ``loads_finite`` by ``json.loads`` at any one site
fails a test here. Each site is held to the answer it already gave a body that
is not JSON, which is read off the same route in the same test rather than
written down, so a drift in either direction fails.

The callback (``POST /challenges/{id}/approve``) is covered by
``tests/test_approval_body_fields.py``; ``POST /token`` reads a form and no JSON
body, so it has no site.
"""

from __future__ import annotations

import sys
from collections.abc import AsyncIterator, Iterator
from dataclasses import replace
from typing import Any

import httpx2
import pytest
from fastmcp.server.auth.providers.jwt import JWTVerifier, RSAKeyPair
from postern_core.auth.device_codes import DeviceCode
from postern_core.auth.device_keys import no_enrolled_devices
from postern_core.identity import CustomerRef
from postern_core.store.engine import Database
from postern_core.store.models import AuditEntry
from sqlalchemy import select
from starlette.applications import Starlette

from services.api.main import create_app
from services.api.settings import Settings
from services.confirm.main import create_confirm_app
from services.confirm.settings import ConfirmSettings
from tests.device_grant_helpers import device_store_of, qr_for, scan_in_store, stored_code
from tests.fixtures import backend_responses as fx
from tests.fixtures.append_only_bypass import (
    delete_audit_rows_by_bypassing_the_append_only_triggers,
)

ISSUER = "https://app.test.invalid"
AUDIENCE = "postern-confirm"
ALICE = "cust_a11ce"
BROWSER_CLIENT = "claude-desktop-42"
JSON = {"content-type": "application/json"}

NON_FINITE = ["NaN", "Infinity", "-Infinity", "1e999", "-1e999"]


# ---------------------------------------------------------------------------
# services/confirm: the three device-grant routes that read a JSON body.
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def key_pair() -> RSAKeyPair:
    return RSAKeyPair.generate()


@pytest.fixture()
def app(pg_url: str, key_pair: RSAKeyPair) -> Starlette:
    verifier = JWTVerifier(public_key=key_pair.public_key, issuer=ISSUER, audience=AUDIENCE)
    return create_confirm_app(
        replace(ConfirmSettings.for_testing(), database_url=pg_url),
        assertion_verifier=verifier,
        device_key_store=no_enrolled_devices(),
    )


@pytest.fixture()
async def clean(database: Database) -> AsyncIterator[Database]:
    await _wipe(database)
    yield database
    await _wipe(database)


async def _wipe(db: Database) -> None:
    async with db.sessionmaker() as s:
        await delete_audit_rows_by_bypassing_the_append_only_triggers(s)
        await s.commit()


def bearer(key_pair: RSAKeyPair, subject: str = ALICE) -> dict[str, str]:
    token = key_pair.create_token(
        subject=subject, issuer=ISSUER, audience=AUDIENCE, expires_in_seconds=60
    )
    return {"Authorization": f"Bearer {token}"}


async def post_raw(
    app: Starlette, path: str, raw: str, headers: dict[str, str] | None = None
) -> httpx2.Response:
    async with httpx2.AsyncClient(
        transport=httpx2.ASGITransport(app=app), base_url="http://t"
    ) as c:
        return await c.post(path, content=raw.encode(), headers={**JSON, **(headers or {})})


async def audit_rows(db: Database) -> list[AuditEntry]:
    async with db.sessionmaker() as s:
        return list((await s.execute(select(AuditEntry).order_by(AuditEntry.id))).scalars().all())


async def new_pairing(app: Starlette) -> DeviceCode:
    resp = await post_raw(app, "/device_authorization", f'{{"client_id": "{BROWSER_CLIENT}"}}')
    assert resp.status_code == 200, resp.text
    return await stored_code(app, resp.json()["user_code"])


@pytest.mark.parametrize("constant", NON_FINITE)
async def test_device_authorization_refuses_a_non_finite_number_as_malformed_json(
    app: Starlette, constant: str
) -> None:
    """The body is otherwise a valid request, so without the refusal it is a 200
    and a pairing exists; with it, the answer is the one ``{not json`` gets."""
    control = await post_raw(app, "/device_authorization", "{not json")
    assert control.status_code == 400
    assert control.json()["error_description"] == "body must be JSON"

    before = dict(device_store_of(app)._codes)  # type: ignore[attr-defined]
    resp = await post_raw(
        app, "/device_authorization", f'{{"client_id": "{BROWSER_CLIENT}", "extra": {constant}}}'
    )

    assert (resp.status_code, resp.json()) == (control.status_code, control.json())
    assert dict(device_store_of(app)._codes) == before  # type: ignore[attr-defined]


@pytest.mark.parametrize("constant", NON_FINITE)
async def test_scan_refuses_a_non_finite_number_as_malformed_json(
    app: Starlette, clean: Database, key_pair: RSAKeyPair, constant: str
) -> None:
    """A scan that is valid in every field, plus one extra number. Unfixed, it
    claims the pairing for Alice and writes a row."""
    code = await new_pairing(app)
    headers = bearer(key_pair)
    control = await post_raw(app, "/scan", "{not json", headers)
    assert control.status_code == 400
    assert control.json()["error_description"] == "body must be JSON"

    resp = await post_raw(
        app,
        "/scan",
        f'{{"user_code": "{code.user_code_display}", "qr": "{qr_for(code)}", "extra": {constant}}}',
        headers,
    )

    assert (resp.status_code, resp.json()) == (control.status_code, control.json())
    assert (await device_store_of(app).get_device_code(code.device_code)).scanned_by == ""  # type: ignore[union-attr]
    assert await audit_rows(clean) == []


@pytest.mark.parametrize("constant", NON_FINITE)
async def test_approve_refuses_a_non_finite_number_as_malformed_json(
    app: Starlette, clean: Database, key_pair: RSAKeyPair, constant: str
) -> None:
    """A pairing the caller scanned, approved with one extra number. Unfixed, it
    is approved and a row is written."""
    code = await new_pairing(app)
    await scan_in_store(app, code.user_code, ALICE)
    headers = bearer(key_pair)
    control = await post_raw(app, "/approve", "{not json", headers)
    assert control.status_code == 400
    assert control.json()["error_description"] == "body must be JSON"

    resp = await post_raw(
        app,
        "/approve",
        f'{{"user_code": "{code.user_code_display}", "extra": {constant}}}',
        headers,
    )

    assert (resp.status_code, resp.json()) == (control.status_code, control.json())
    assert (await device_store_of(app).get_device_code(code.device_code)).approved is False  # type: ignore[union-attr]
    assert await audit_rows(clean) == []


# ---------------------------------------------------------------------------
# services/api: the header/body validation middleware.
# ---------------------------------------------------------------------------


def _parse_error_shape(response: httpx2.Response) -> tuple[int, int, Any, str]:
    """Status, JSON-RPC code, id and message prefix. The message TAIL is the
    parser's own detail ("key must be a string at line 1 column 2") and is
    not part of what a client can rely on."""
    body = response.json()
    return (
        response.status_code,
        body["error"]["code"],
        body["id"],
        body["error"]["message"].split(":")[0],
    )


PARSE_ERROR = (400, -32700, None, "Parse error")
MCP_HEADERS = {
    "Accept": "application/json, text/event-stream",
    "Content-Type": "application/json",
    "Mcp-Method": "tools/call",
    "Mcp-Name": "accounts.list",
}


def _call(extra: str) -> str:
    return (
        '{"jsonrpc":"2.0","id":1,"method":"tools/call",'
        '"params":{"name":"accounts.list","arguments":{},"_meta":{"x":' + extra + "}}}"
    )


async def _api_post(pg_url: str, raw: str) -> tuple[httpx2.Response, list[str], list[AuditEntry]]:
    backend_paths: list[str] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        backend_paths.append(request.url.path)
        return httpx2.Response(200, json=fx.ACCOUNTS)

    app = create_app(
        Settings(backend_base_url="https://backend.test", database_url=pg_url),
        resolver=lambda: CustomerRef(value="cust_7f3a"),
        transport=httpx2.MockTransport(handler),
    )
    db = Database(pg_url)
    async with db.sessionmaker() as s:
        await delete_audit_rows_by_bypassing_the_append_only_triggers(s)
        await s.commit()
    try:
        async with app.router.lifespan_context(app):
            async with httpx2.AsyncClient(
                transport=httpx2.ASGITransport(app=app), base_url="http://test"
            ) as client:
                response = await client.post("/mcp", headers=MCP_HEADERS, content=raw.encode())
        return response, backend_paths, await audit_rows(db)
    finally:
        async with db.sessionmaker() as s:
            await delete_audit_rows_by_bypassing_the_append_only_triggers(s)
            await s.commit()
        await db.close()


async def test_the_api_control_a_finite_number_reaches_the_tool(pg_url: str) -> None:
    """Without this the refusals below could be a broken request."""
    response, backend_paths, rows = await _api_post(pg_url, _call("1"))

    assert response.status_code == 200, response.text
    assert backend_paths == ["/accounts"]
    assert len(rows) >= 1


@pytest.mark.parametrize("constant", NON_FINITE)
async def test_the_api_refuses_a_non_finite_number_as_a_parse_error(
    pg_url: str, constant: str
) -> None:
    malformed, _, _ = await _api_post(pg_url, "{not json")
    assert _parse_error_shape(malformed) == PARSE_ERROR

    response, backend_paths, rows = await _api_post(pg_url, _call(constant))

    assert _parse_error_shape(response) == PARSE_ERROR
    assert backend_paths == []
    assert rows == []


@pytest.mark.parametrize("constant", NON_FINITE)
async def test_the_api_refuses_a_non_finite_number_in_a_body_that_is_not_a_tool_call(
    pg_url: str, constant: str
) -> None:
    """The refusal is the parser's, not a property of ``tools/call``."""
    raw = '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"x":' + constant + "}}"
    response, backend_paths, rows = await _api_post(pg_url, raw)

    assert _parse_error_shape(response) == PARSE_ERROR
    assert backend_paths == []
    assert rows == []


# ---------------------------------------------------------------------------
# services/api: a body the strict parser cannot read never reaches FastMCP.
# ---------------------------------------------------------------------------

DIGIT_PAD = "7" * 700


@pytest.fixture()
def small_int_digit_limit() -> Iterator[None]:
    """640 is the smallest limit Python allows; same as PYTHONINTMAXSTRDIGITS=640."""
    previous = sys.get_int_max_str_digits()
    sys.set_int_max_str_digits(640)
    try:
        yield
    finally:
        sys.set_int_max_str_digits(previous)


def _padded_call(meta_x: str) -> str:
    return (
        '{"pad":' + DIGIT_PAD + ',"jsonrpc":"2.0","id":1,"method":"tools/call",'
        '"params":{"name":"accounts.list","arguments":{},"_meta":{"x":' + meta_x + "}}}"
    )


@pytest.mark.usefixtures("small_int_digit_limit")
@pytest.mark.parametrize("meta_x", ["NaN", "1"])
async def test_a_body_the_strict_parser_cannot_read_is_not_handed_to_a_second_parser(
    pg_url: str, meta_x: str
) -> None:
    """The reviewer's exploit. The stdlib refuses a 700-digit integer once the
    limit is 640, so the middleware cannot read the body; FastMCP's own
    parser (jiter) has a fixed limit of its own, reads it, and accepts `NaN`.
    Unfixed, the body was passed through: 200, the backend reached, two audit
    rows. The `1` variant is the same body with nothing non-finite in it: the
    refusal is of an unparseable body, not of the constant."""
    response, backend_paths, rows = await _api_post(pg_url, _padded_call(meta_x))

    assert _parse_error_shape(response) == PARSE_ERROR
    assert response.json()["error"]["message"] == "Parse error"
    assert backend_paths == []
    assert rows == []


@pytest.mark.usefixtures("small_int_digit_limit")
async def test_a_normal_body_still_passes_under_the_same_digit_limit(pg_url: str) -> None:
    response, backend_paths, rows = await _api_post(pg_url, _call("1"))

    assert response.status_code == 200, response.text
    assert backend_paths == ["/accounts"]
    assert len(rows) >= 1


async def test_a_nesting_depth_the_parser_cannot_read_is_answered_by_the_middleware(
    pg_url: str,
) -> None:
    """200,000 nested arrays: `RecursionError`, refused with the middleware's
    own fixed message and not FastMCP's detailed one."""
    deep = '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"accounts.list",'
    deep += '"arguments":{"x":' + "[" * 200_000 + "}}}"
    response, backend_paths, rows = await _api_post(pg_url, deep)

    assert _parse_error_shape(response) == PARSE_ERROR
    assert response.json()["error"]["message"] == "Parse error"
    assert backend_paths == []
    assert rows == []


async def test_an_underflowing_number_is_finite_and_passes(pg_url: str) -> None:
    """`1e-999` is 0.0, which is finite: not refused by the parser or the api."""
    response, backend_paths, _ = await _api_post(pg_url, _call("1e-999"))

    assert response.status_code == 200, response.text
    assert backend_paths == ["/accounts"]


# ---------------------------------------------------------------------------
# services/confirm: nesting past the recursion limit is the same malformed body.
# ---------------------------------------------------------------------------

DEEP_BODY = "[" * 20_000


async def test_device_authorization_answers_a_too_deep_body_as_malformed_json(
    app: Starlette,
) -> None:
    control = await post_raw(app, "/device_authorization", "{not json")
    before = dict(device_store_of(app)._codes)  # type: ignore[attr-defined]

    resp = await post_raw(app, "/device_authorization", DEEP_BODY)

    assert (resp.status_code, resp.json()) == (control.status_code, control.json())
    assert dict(device_store_of(app)._codes) == before  # type: ignore[attr-defined]


async def test_scan_answers_a_too_deep_body_as_malformed_json(
    app: Starlette, clean: Database, key_pair: RSAKeyPair
) -> None:
    code = await new_pairing(app)
    headers = bearer(key_pair)
    control = await post_raw(app, "/scan", "{not json", headers)

    resp = await post_raw(app, "/scan", DEEP_BODY, headers)

    assert (resp.status_code, resp.json()) == (control.status_code, control.json())
    assert (await device_store_of(app).get_device_code(code.device_code)).scanned_by == ""  # type: ignore[union-attr]
    assert await audit_rows(clean) == []


async def test_approve_answers_a_too_deep_body_as_malformed_json(
    app: Starlette, clean: Database, key_pair: RSAKeyPair
) -> None:
    code = await new_pairing(app)
    await scan_in_store(app, code.user_code, ALICE)
    headers = bearer(key_pair)
    control = await post_raw(app, "/approve", "{not json", headers)

    resp = await post_raw(app, "/approve", DEEP_BODY, headers)

    assert (resp.status_code, resp.json()) == (control.status_code, control.json())
    assert (await device_store_of(app).get_device_code(code.device_code)).approved is False  # type: ignore[union-attr]
    assert await audit_rows(clean) == []

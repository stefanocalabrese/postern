"""The device grant's audit-failure log lines, with the record factory OFF.

`services/confirm/device_auth.py` logs when an audit write fails, on eight
paths: `POST /token` for a code (`_token_response`) and for a refresh
(`_refresh_grant`), `POST /approve` (`approve_callback`) and `POST /scan`
(`scan_callback`), each twice: once when the request RAISED and the refused-row
write then failed too, and once when the request ANSWERED and its own row could
not be written. Before this file those eight lines were protected only by a
source scan; here each is driven for real, against the assembled app and a real
Postgres, with a real driver error carrying a sentinel in a bound parameter, and
the assertion is on every record the process emitted.

The record factory is switched off after the app is built (building it installs
it), so what is measured is the call site and not the net.
"""

import logging
from collections.abc import Iterator
from typing import Any
from unittest.mock import patch

import httpx2
import pytest
from sqlalchemy import text
from starlette.applications import Starlette

from services.confirm import device_auth
from tests.device_grant_helpers import qr_for
from tests.test_pairing_audit import (  # noqa: F401  (fixtures)
    app,
    approve,
    bearer,
    clean,
    db,
    exchange,
    issue,
    key_pair,
    paired,
    pg_url,
    settings,
)

SENTINEL = "zzsentinel_device_5519"


@pytest.fixture
def net_off(app: Starlette) -> Iterator[None]:  # noqa: F811
    """No sanitising record factory, put back afterwards. Depends on `app`
    because building the app installs it."""
    previous = logging.getLogRecordFactory()
    logging.setLogRecordFactory(logging.LogRecord)
    yield
    logging.setLogRecordFactory(previous)


async def _driver_error_append(session: Any, **kwargs: Any) -> None:
    await session.execute(text("SELECT CAST(:p AS int)"), {"p": SENTINEL})


async def _raises(*args: Any, **kwargs: Any) -> Any:
    raise RuntimeError("the request itself failed")


def _assert_clean(caplog: pytest.LogCaptureFixture, response: httpx2.Response) -> None:
    assert response.status_code == 500
    assert SENTINEL not in response.text
    logged = caplog.text
    assert SENTINEL not in logged, logged
    for fragment in ("[SQL:", "[parameters:", "invalid input for query argument"):
        assert fragment not in logged, (fragment, logged)
    assert "audit write failed" in logged
    assert "asyncpg.exceptions.DataError client-side" in logged


async def _scan_request(app: Starlette, key_pair: Any, code: Any) -> httpx2.Response:  # noqa: F811
    async with httpx2.AsyncClient(
        transport=httpx2.ASGITransport(app=app, raise_app_exceptions=False), base_url="http://t"
    ) as client:
        return await client.post(
            "/scan",
            json={"user_code": code.user_code_display, "qr": qr_for(code)},
            headers=bearer(key_pair),
        )


async def _refresh_request(app: Starlette, refresh_token: str) -> httpx2.Response:  # noqa: F811
    async with httpx2.AsyncClient(
        transport=httpx2.ASGITransport(app=app, raise_app_exceptions=False), base_url="http://t"
    ) as client:
        return await client.post(
            "/token", data={"grant_type": "refresh_token", "refresh_token": refresh_token}
        )


# ------------------------------------------------------------------ /approve


@pytest.mark.usefixtures("net_off")
async def test_approve_callback_answered_site(
    app: Starlette,  # noqa: F811
    clean: Any,  # noqa: F811
    key_pair: Any,  # noqa: F811
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.DEBUG)
    code = await issue(app)
    with patch.object(_store(), "append", _driver_error_append):
        response = await approve(
            app, {"user_code": code.user_code_display}, bearer(key_pair), as_a_server_would=True
        )
    _assert_clean(caplog, response)
    assert "answered" in caplog.text


@pytest.mark.usefixtures("net_off")
async def test_approve_callback_raised_site(
    app: Starlette,  # noqa: F811
    clean: Any,  # noqa: F811
    key_pair: Any,  # noqa: F811
    caplog: pytest.LogCaptureFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    caplog.set_level(logging.DEBUG)
    code = await issue(app)
    monkeypatch.setattr(app.state.device_code_store, "approve_scanned", _raises)
    with patch.object(_store(), "append", _driver_error_append):
        response = await approve(
            app, {"user_code": code.user_code_display}, bearer(key_pair), as_a_server_would=True
        )
    _assert_clean(caplog, response)
    assert "after it raised RuntimeError" in caplog.text


# --------------------------------------------------------------------- /scan


@pytest.mark.usefixtures("net_off")
async def test_scan_callback_answered_site(
    app: Starlette,  # noqa: F811
    clean: Any,  # noqa: F811
    key_pair: Any,  # noqa: F811
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.DEBUG)
    code = await issue(app, scanned_by=None)
    with patch.object(_store(), "append", _driver_error_append):
        response = await _scan_request(app, key_pair, code)
    _assert_clean(caplog, response)
    assert "scan that answered" in caplog.text


@pytest.mark.usefixtures("net_off")
async def test_scan_callback_raised_site(
    app: Starlette,  # noqa: F811
    clean: Any,  # noqa: F811
    key_pair: Any,  # noqa: F811
    caplog: pytest.LogCaptureFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    caplog.set_level(logging.DEBUG)
    code = await issue(app, scanned_by=None)
    monkeypatch.setattr(device_auth, "_scan", _raises)
    with patch.object(_store(), "append", _driver_error_append):
        response = await _scan_request(app, key_pair, code)
    _assert_clean(caplog, response)
    assert "scan after it raised RuntimeError" in caplog.text


# --------------------------------------------------- /token, device_code grant


@pytest.mark.usefixtures("net_off")
async def test_token_response_answered_site(
    app: Starlette,  # noqa: F811
    clean: Any,  # noqa: F811
    key_pair: Any,  # noqa: F811
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.DEBUG)
    code = await paired(app, key_pair)
    with patch.object(_store(), "append", _driver_error_append):
        response = await exchange(app, code.device_code, as_a_server_would=True)
    _assert_clean(caplog, response)
    assert "token exchange that answered" in caplog.text


@pytest.mark.usefixtures("net_off")
async def test_token_response_raised_site(
    app: Starlette,  # noqa: F811
    clean: Any,  # noqa: F811
    key_pair: Any,  # noqa: F811
    caplog: pytest.LogCaptureFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    caplog.set_level(logging.DEBUG)
    code = await paired(app, key_pair)
    monkeypatch.setattr(device_auth, "_exchange", _raises)
    with patch.object(_store(), "append", _driver_error_append):
        response = await exchange(app, code.device_code, as_a_server_would=True)
    _assert_clean(caplog, response)
    assert "token exchange after it raised RuntimeError" in caplog.text


# --------------------------------------------------- /token, refresh_token grant


async def _refresh_token_of(app: Starlette, key_pair: Any) -> str:  # noqa: F811
    code = await paired(app, key_pair)
    issued = await exchange(app, code.device_code)
    assert issued.status_code == 200, issued.text
    token = issued.json()["refresh_token"]
    assert isinstance(token, str)
    return token


@pytest.mark.usefixtures("net_off")
async def test_refresh_grant_answered_site(
    app: Starlette,  # noqa: F811
    clean: Any,  # noqa: F811
    key_pair: Any,  # noqa: F811
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.DEBUG)
    refresh_token = await _refresh_token_of(app, key_pair)
    with patch.object(_store(), "append", _driver_error_append):
        response = await _refresh_request(app, refresh_token)
    _assert_clean(caplog, response)
    assert "session refresh that answered" in caplog.text


@pytest.mark.usefixtures("net_off")
async def test_refresh_grant_raised_site(
    app: Starlette,  # noqa: F811
    clean: Any,  # noqa: F811
    key_pair: Any,  # noqa: F811
    caplog: pytest.LogCaptureFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    caplog.set_level(logging.DEBUG)
    refresh_token = await _refresh_token_of(app, key_pair)
    monkeypatch.setattr(device_auth, "_refresh", _raises)
    with patch.object(_store(), "append", _driver_error_append):
        response = await _refresh_request(app, refresh_token)
    _assert_clean(caplog, response)
    assert "session refresh after it raised RuntimeError" in caplog.text


def _store() -> Any:
    from postern_core.store import audit as audit_store

    return audit_store

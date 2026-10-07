"""A backend 403 is mapped to `not found`, and leaves one warning behind.

`services/api/tools/not_found.py` answers the model with the same fixed
sentence for a 403 as for a 404 (an existence oracle otherwise, A5). The cost
was that a misconfigured minter, whose tokens the backend rejects on EVERY
call, looked like customers mistyping refs: the audit row of a 403 is the same
as a 404's and FastMCP's own log line names no status. So a 403, and only a
403, logs one fixed warning on `services.api.tools.not_found`, at most once per
60 seconds per process. It carries no ref, no tool arguments and no backend
body. The audit schema is untouched: the log line is the signal.
"""

import logging
from typing import Any

import httpx2
import pytest
from fastmcp.exceptions import ToolError
from fastmcp.server.auth.providers.jwt import RSAKeyPair
from postern_core.facade.client import BackendError

from services.api.tools import not_found
from services.api.tools.not_found import NOT_FOUND, not_found_is_a_fixed_refusal
from tests.test_audit_reserve import token_for
from tests.test_not_found_mapping import (  # noqa: F401  (fixtures)
    CUSTOMER,
    FOREIGN_REF,
    UNKNOWN_REF,
    _call,
    _text,
    key_pair,
    serving,
)

LOGGER = "services.api.tools.not_found"
MARKER = "backend answered 403 on a caller-chosen ref"
BODY_SENTINEL = "zzsentinel_backend_body_8841"


class _Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


@pytest.fixture(autouse=True)
def clock(monkeypatch: pytest.MonkeyPatch) -> _Clock:
    """A clock the test owns, and a rate-limit state that starts empty."""
    fake = _Clock()
    monkeypatch.setattr(not_found, "_clock", fake)
    monkeypatch.setattr(not_found, "_last_warned_at", None)
    return fake


async def _refuse(status: int) -> None:
    async with not_found_is_a_fixed_refusal():
        raise BackendError(status, "guidance")


def _warnings(caplog: pytest.LogCaptureFixture) -> list[logging.LogRecord]:
    return [r for r in caplog.records if r.name == LOGGER]


async def test_a_403_logs_one_warning(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.DEBUG)
    with pytest.raises(ToolError, match=NOT_FOUND):
        await _refuse(403)
    records = _warnings(caplog)
    assert len(records) == 1
    assert records[0].levelno == logging.WARNING
    text = records[0].getMessage()
    assert MARKER in text
    assert "audience and scope" in text
    assert records[0].args in ((), None)
    assert records[0].exc_info is None


async def test_a_404_logs_nothing(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.DEBUG)
    with pytest.raises(ToolError, match=NOT_FOUND):
        await _refuse(404)
    assert _warnings(caplog) == []


@pytest.mark.parametrize("status", [400, 401, 500, 503])
async def test_other_statuses_log_nothing_here_and_stay_a_backend_error(
    caplog: pytest.LogCaptureFixture, status: int
) -> None:
    caplog.set_level(logging.DEBUG)
    with pytest.raises(BackendError):
        await _refuse(status)
    assert _warnings(caplog) == []


async def test_a_second_403_inside_the_window_logs_nothing_and_one_after_it_logs_again(
    caplog: pytest.LogCaptureFixture, clock: _Clock
) -> None:
    caplog.set_level(logging.DEBUG)
    for _ in range(3):
        with pytest.raises(ToolError):
            await _refuse(403)
    assert len(_warnings(caplog)) == 1

    clock.now += 59.9
    with pytest.raises(ToolError):
        await _refuse(403)
    assert len(_warnings(caplog)) == 1, "still inside the 60 s window"

    clock.now += 0.2
    with pytest.raises(ToolError):
        await _refuse(403)
    assert len(_warnings(caplog)) == 2, "the window has passed"

    with pytest.raises(ToolError):
        await _refuse(403)
    assert len(_warnings(caplog)) == 2, "and the window restarts from the last warning"


async def test_a_404_does_not_spend_the_window(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.DEBUG)
    with pytest.raises(ToolError):
        await _refuse(404)
    with pytest.raises(ToolError):
        await _refuse(403)
    assert len(_warnings(caplog)) == 1


async def test_a_403_through_the_real_app_is_the_same_bytes_as_a_404_and_logs_no_ref(
    serving: Any,  # noqa: F811
    key_pair: RSAKeyPair,  # noqa: F811
    caplog: pytest.LogCaptureFixture,
) -> None:
    def handler(request: httpx2.Request) -> httpx2.Response:
        status = 403 if FOREIGN_REF in str(request.url) else 404
        return httpx2.Response(status, json={"detail": BODY_SENTINEL})

    app = await serving(handler)
    token = token_for(key_pair, CUSTOMER)
    caplog.set_level(logging.DEBUG)

    unknown = await _call(app, token, "accounts.get_balance", UNKNOWN_REF)
    assert _warnings(caplog) == [], "a 404 leaves no warning"
    foreign = await _call(app, token, "accounts.get_balance", FOREIGN_REF)

    assert _text(foreign) == NOT_FOUND
    assert foreign.content == unknown.content
    records = _warnings(caplog)
    assert len(records) == 1
    everything = " ".join(r.getMessage() for r in records) + caplog.text
    # The warning is fixed text: no ref, no argument name, no body, no customer.
    for forbidden in (FOREIGN_REF, UNKNOWN_REF, BODY_SENTINEL, CUSTOMER, "account_ref"):
        assert forbidden not in records[0].getMessage()
    assert BODY_SENTINEL not in everything

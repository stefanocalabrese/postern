"""A device code is a bearer credential: no store path logs it, only its handle.

`device_code` is the whole authority to exchange at `POST /token` for a
customer session, and a code the contention path logs is one that is live and
already approved. Four `RedisDeviceCodeStore` methods log on a stored value
that will not deserialize (`get_device_code`, `consume_device_code`,
`claim_scan`, `approve_scanned`) and one of them (`consume_device_code`) also
logs when every attempt is beaten by another writer. Each is driven here with a
sentinel code, and the assertion is on every record, at DEBUG, on the root
logger: the sentinel is absent and the handle is present.

The second half is a scan by `ast`, beside `test_log_call_scan.py`: no logger
call in `auth/` or `services/confirm/` passes a secret-named value except
through the handle function.
"""

import ast
import logging
from pathlib import Path
from typing import Any

import pytest
from postern_core.auth.device_codes import RedisDeviceCodeStore, _device_code_handle
from redis.exceptions import WatchError

ROOT = Path(__file__).resolve().parent.parent
SENTINEL = "zzdevcode_sentinel_7741_abcdefghijklmnopqrstuv"


class _Pipe:
    """A pipeline whose `get` answers ``value`` and whose `watch` may conflict."""

    def __init__(self, value: str | None, *, conflict: bool) -> None:
        self._value = value
        self._conflict = conflict

    async def __aenter__(self) -> "_Pipe":
        return self

    async def __aexit__(self, *exc: object) -> None:
        return None

    async def watch(self, key: str) -> None:
        if self._conflict:
            raise WatchError("a writer moved the key")

    async def get(self, key: str) -> str | None:
        return self._value


class _Redis:
    def __init__(self, value: str | None, *, conflict: bool = False) -> None:
        self._value = value
        self._conflict = conflict

    def pipeline(self, *args: Any, **kwargs: Any) -> _Pipe:
        return _Pipe(self._value, conflict=self._conflict)

    async def get(self, key: str) -> str | None:
        return self._value


def _store(
    monkeypatch: pytest.MonkeyPatch, value: str | None, *, conflict: bool = False
) -> RedisDeviceCodeStore:
    store = object.__new__(RedisDeviceCodeStore)
    store._redis = _Redis(value, conflict=conflict)
    monkeypatch.setattr(RedisDeviceCodeStore, "_key", lambda self, value: f"k:{value}")
    return store


def _assert_handle_only(caplog: pytest.LogCaptureFixture, expected: str) -> None:
    messages = [record.getMessage() for record in caplog.records]
    assert messages, "the site logged nothing"
    for text in (caplog.text, *messages):
        assert SENTINEL not in text, text
    assert expected in " ".join(messages)
    assert _device_code_handle(SENTINEL) in " ".join(messages)


async def test_get_device_code_logs_the_handle(
    caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    caplog.set_level(logging.DEBUG)
    store = _store(monkeypatch, "{ not json")
    assert await store.get_device_code(SENTINEL) is None
    _assert_handle_only(caplog, "Failed to deserialize device code")


async def test_consume_device_code_logs_the_handle_on_a_corrupt_value(
    caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    caplog.set_level(logging.DEBUG)
    store = _store(monkeypatch, "{ not json")
    assert await store.consume_device_code(SENTINEL, session_id="s") is False
    _assert_handle_only(caplog, "refusing to claim device code")


async def test_consume_device_code_logs_the_handle_when_every_attempt_is_beaten(
    caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    caplog.set_level(logging.DEBUG)
    store = _store(monkeypatch, "{}", conflict=True)
    assert await store.consume_device_code(SENTINEL, session_id="s") is False
    _assert_handle_only(caplog, "attempts were each beaten")


async def test_claim_scan_logs_the_handle_on_a_corrupt_value(
    caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    caplog.set_level(logging.DEBUG)
    store = _store(monkeypatch, "{ not json")
    await store.claim_scan(SENTINEL, "customer", scanner_ip=None)
    _assert_handle_only(caplog, "refusing a scan of device code")


async def test_approve_scanned_logs_the_handle_on_a_corrupt_value(
    caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    caplog.set_level(logging.DEBUG)
    store = _store(monkeypatch, "{ not json")
    assert await store.approve_scanned(SENTINEL, "customer") is False
    _assert_handle_only(caplog, "refusing to approve device code")


# ---------------------------------------------------------------------------
# A scan: no logger call hands a secret-named value over except as a handle.
# ---------------------------------------------------------------------------

SECRET_NAMES = frozenset({"device_code", "user_code", "refresh_token", "token", "secret"})
HANDLE_CALLS = frozenset({"_device_code_handle", "device_code_handle"})
LOG_METHODS = frozenset(
    {"debug", "info", "warning", "warn", "error", "exception", "critical", "fatal", "log"}
)


def _terminal(node: ast.expr) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return ""


def _is_log_call(node: ast.Call) -> bool:
    func = node.func
    return (
        isinstance(func, ast.Attribute)
        and func.attr in LOG_METHODS
        and "log" in _terminal(func.value).lower()
    )


def _names_a_secret(node: ast.AST) -> bool:
    """True if ``node`` mentions a secret-named value outside a handle call."""
    if isinstance(node, ast.Call) and _terminal(node.func) in HANDLE_CALLS:
        return False
    if isinstance(node, ast.Name):
        return node.id in SECRET_NAMES
    if isinstance(node, ast.Attribute) and node.attr in SECRET_NAMES:
        return True
    return any(_names_a_secret(child) for child in ast.iter_child_nodes(node))


def secret_log_calls(source: str) -> list[int]:
    """Line numbers of logger calls that pass a secret-named value raw."""
    found: list[int] = []
    for node in ast.walk(ast.parse(source)):
        if not (isinstance(node, ast.Call) and _is_log_call(node)):
            continue
        values = [*node.args, *(kw.value for kw in node.keywords)]
        if any(_names_a_secret(value) for value in values):
            found.append(node.lineno)
    return found


def _scanned() -> list[Path]:
    return [
        *sorted((ROOT / "packages/postern-core/src/postern_core/auth").rglob("*.py")),
        *sorted((ROOT / "services/confirm").rglob("*.py")),
    ]


def test_no_logger_call_in_auth_or_confirm_passes_a_secret_raw() -> None:
    offenders = [
        f"{path.relative_to(ROOT)}:{line}"
        for path in _scanned()
        for line in secret_log_calls(path.read_text())
    ]
    assert not offenders, offenders


@pytest.mark.parametrize(
    "call",
    [
        'logger.warning("x %s", device_code)',
        'logger.warning("x %s", code.device_code)',
        'logger.warning(f"x {device_code}")',
        'logger.info("x %s", user_code)',
        'self.logger.error("x", refresh_token)',
        'logger.debug("x %s", token)',
        'logger.warning("x", extra={"k": secret})',
    ],
)
def test_the_secret_scan_flags(call: str) -> None:
    assert secret_log_calls(call + "\n")


@pytest.mark.parametrize(
    "call",
    [
        'logger.warning("x %s", _device_code_handle(device_code))',
        'logger.warning("x %s", device_code_handle(code.device_code))',
        'logger.warning("x %s", handle)',
        "results.append(device_code)",
    ],
)
def test_the_secret_scan_passes(call: str) -> None:
    assert not secret_log_calls(call + "\n")

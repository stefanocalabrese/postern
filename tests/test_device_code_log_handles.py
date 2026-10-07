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
import hashlib
import logging
import re
from pathlib import Path
from typing import Any

import pytest
from postern_core.auth.device_codes import RedisDeviceCodeStore, _device_code_handle
from redis.exceptions import WatchError

from tests.test_log_call_scan import _log_method, _logger_names, _logging_aliases

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

#: A name that SOUNDS like a credential: matched as a substring of an
#: identifier, an attribute in a chain, a string subscript (`form["device_code"]`)
#: or a called function's name. Substring, not equality, because the exact-name
#: scan this replaces let `device_code_value`, `access_token` and
#: `form["device_code"]` through.
SECRET_RE = re.compile(
    r"device_code|user_code|refresh|token|secret|assertion|signature|password|private"
    r"|pem|bearer|authorization|jwt",
    re.IGNORECASE,
)

#: Calls whose RESULT is safe to log whatever they were given: the whole call,
#: arguments included, is skipped. Each says why.
SAFE_CALLS: dict[str, str] = {
    "_device_code_handle": "SHA-256 prefix of the device code (64 bits of a 256-bit secret)",
    "device_code_handle": "the same function, public spelling (services/confirm/audit.py)",
}

#: Identifiers that match `SECRET_RE` and are safe as a logged value. Each says
#: why. Derived by running the scan over `services/`, `packages/*/src`, `tools/`
#: and `stub/` and reading every hit (four on 7 October 2026); a hit is added
#: here only if it is not a credential.
SAFE_NAMES: dict[str, str] = {
    "device_code_handle": (
        "the RefreshSession field, filled from `device_code_handle(code.device_code)` "
        "when the family is created in `services/confirm/device_auth.py`: the SHA-256 "
        "prefix, never the code"
    ),
    "ASSERTION_CLOCK_SKEW_SECONDS": "an int constant, the tier-2 auth_time tolerance in seconds",
    "pem_env_var": (
        "the NAME of the environment variable that holds a PEM path "
        "(`POSTERN_READ_KEY_PEM_PATH`), not the PEM"
    ),
}


def _secret_mentions(node: ast.AST) -> list[str]:
    """Every credential-sounding name ``node`` mentions outside a safe call."""
    if isinstance(node, ast.Call):
        callee = _terminal(node.func)
        if callee in SAFE_CALLS:
            return []
    hits: list[str] = []
    if isinstance(node, ast.Name):
        hits.append(node.id)
    elif isinstance(node, ast.Attribute):
        hits.append(node.attr)
    elif (
        isinstance(node, ast.Subscript)
        and isinstance(node.slice, ast.Constant)
        and isinstance(node.slice.value, str)
    ):
        hits.append(node.slice.value)
    for child in ast.iter_child_nodes(node):
        hits.extend(_secret_mentions(child))
    return [name for name in hits if SECRET_RE.search(name) and name not in SAFE_NAMES]


def _terminal(node: ast.expr) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return ""


def secret_log_calls(source: str) -> list[int]:
    """Line numbers of logging calls that pass a credential-named value raw.

    What counts as a logging call is `test_log_call_scan._log_method`: a
    `getLogger(...)` receiver, a name bound from one, `print`, `warnings.warn`,
    `sys.stderr.write`, `getattr(logger, "error")(...)`, an imported alias.
    """
    tree = ast.parse(source)
    aliases = _logging_aliases(tree)
    known = _logger_names(tree)
    found: list[int] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if _log_method(node, aliases, known) is None:
            continue
        values = [*node.args, *(kw.value for kw in node.keywords if kw.arg != "exc_info")]
        if any(_secret_mentions(value) for value in values):
            found.append(node.lineno)
    return found


def _scanned() -> list[Path]:
    return [
        *sorted((ROOT / "services").rglob("*.py")),
        *sorted(ROOT.glob("packages/*/src/**/*.py")),
        *sorted((ROOT / "tools").rglob("*.py")),
        *sorted((ROOT / "stub").rglob("*.py")),
    ]


def test_no_logging_call_in_the_repo_passes_a_credential_raw() -> None:
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
        # The shapes the exact-name scan let through.
        'logger.warning("x %s", device_code_value)',
        'logger.warning("x %s", access_token)',
        'logger.warning("x %s", session_token)',
        'logger.warning("x %s", refresh)',
        'logger.warning("x %s", form["device_code"])',
        'logging.getLogger(__name__).warning("x %s", device_code)',
        "print(device_code)",
        'warnings.warn(f"x {device_code}")',
        "sys.stderr.write(device_code)",
        'logger.warning("x %s", str(device_code_value))',
        'logger.warning("x %s", family.refresh_hash)',
        'logger.warning("x %s", request.headers.authorization)',
        'logger.warning("x %s", load_private_key())',
        'logger.warning("x %s", handle_of(device_code))',
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
        'logger.warning("x %s", family.device_code_handle)',
        'logger.warning("x %s", family.sid)',
        'logger.warning("x %s", display_handle)',
        'logger.warning("x %s", ASSERTION_CLOCK_SKEW_SECONDS)',
        'warnings.warn(f"x {pem_env_var} is unset")',
        'logging.getLogger(__name__).warning("x %s", device_code_handle(device_code_value))',
        'print("tokens are fine in a message string")',
        'logger.warning("x", exc_info=refresh_failure)',
    ],
)
def test_the_secret_scan_passes(call: str) -> None:
    assert not secret_log_calls(call + "\n")


@pytest.mark.parametrize(
    "line",
    [
        # The two device_auth.py sites a raw `device_code_value` left unflagged.
        'logger.warning("approved with no customer reference: %s", device_code_value)',
        'logger.error("could not be audited AND could not be withdrawn: %s", device_code_value)',
    ],
)
def test_the_secret_scan_flags_the_surviving_mutants(line: str) -> None:
    assert secret_log_calls(line + "\n")


def test_the_handle_is_a_sha256_prefix_not_a_slice_of_the_code() -> None:
    """The handle must be unlinkable to the code by anything but a hash."""
    handle = _device_code_handle(SENTINEL)
    assert handle == hashlib.sha256(SENTINEL.encode()).hexdigest()[:16]
    assert SENTINEL[:8] not in handle
    assert SENTINEL[:4] not in handle

"""Every numeric setting both services read refuses what it cannot run on.

THE DEFECT CLASS. `d35bc3a` floored ``POSTERN_DEVICE_CODE_TTL_SECONDS`` and in
doing so surfaced that it was one of many: eighteen more numbers across
`services/api/settings.py` and `services/confirm/settings.py` were read with a
bare ``int()`` or ``float()``, each crashing on an empty string with a message
naming neither the variable nor the service, and each silently accepting zero
or a negative. `postern_core/config.py` carries what the two readers do; this
file carries the inventory and the bound each variable got.

WHAT THE INVENTORY BELOW IS FOR. `BOUNDED` is the whole set, one record per
variable, and every test here is parametrized over it. A new numeric setting
that is added to a ``from_env`` and not to this tuple fails
`TestEveryNumericSettingIsInTheInventory`, which walks the two ``from_env``
methods rather than trusting anyone to remember.

WHAT IT DELIBERATELY DOES NOT PIN. These are bounds on what is
REPRESENTABLE, in the sense `services/confirm/settings.py`'s
`MIN_DEVICE_CODE_TTL_SECONDS` uses the word: they refuse values the process
cannot serve a request on. None of them says a value inside the bound is
WISE. `POSTERN_MAX_BODY_BYTES=1` parses, and a deployment running it answers
413 to every tool call whose body exceeds one byte.
"""

from __future__ import annotations

import ast
import dataclasses
import inspect
from pathlib import Path
from typing import Any

import pytest
from postern_core.config import float_from_env, int_from_env
from postern_core.store.audit import MAX_ARGUMENTS_BYTES

from services.api.settings import Settings
from services.confirm.settings import (
    DEFAULT_DEVICE_SCOPES,
    MIN_DEVICE_CODE_TTL_SECONDS,
    MIN_SCOPES_LENGTH,
    ConfirmSettings,
)

# The api service's `from_env` reads this one with a bare `os.environ[...]`,
# so every case here has to supply it or fail on the wrong thing.
BACKEND_BASE_URL = "https://backend.test"


@dataclasses.dataclass(frozen=True)
class Bounded:
    """One environment variable, its bound, and what that bound refuses.

    ``refuses`` and ``accepts`` are written out rather than computed from
    ``minimum``, because the interesting values differ per variable: the
    floors that matter are 0 and -1 for a hop count, 0 and 0.0 for a deadline,
    and 41 for a scope ceiling whose floor is the length of a string.
    """

    name: str
    field: str
    service: str
    default: int | float
    refuses: tuple[str, ...]
    accepts: tuple[str, ...]


#: Every numeric setting either ``from_env`` reads, with the bound it got.
#:
#: The three variables read by BOTH services -- the database timeouts -- are
#: listed once per service, because they are two independent parses and a
#: bound that disagreed between them would be the defect, not the fix.
BOUNDED: tuple[Bounded, ...] = (
    # --- services/api ------------------------------------------------------
    Bounded(
        "POSTERN_CACHE_TTL_SECONDS", "cache_ttl_seconds", "api", 60, ("0", "-1"), ("1", "3600")
    ),
    Bounded("POSTERN_TRUSTED_PROXY_HOPS", "trusted_proxy_hops", "api", 0, ("-1",), ("0", "1", "4")),
    Bounded(
        "POSTERN_BACKEND_CONNECT_TIMEOUT_SECONDS",
        "backend_connect_timeout_seconds",
        "api",
        2.0,
        ("0", "0.0", "-1", "nan", "inf"),
        ("0.001", "2.0", "30"),
    ),
    Bounded(
        "POSTERN_BACKEND_WRITE_TIMEOUT_SECONDS",
        "backend_write_timeout_seconds",
        "api",
        2.0,
        ("0", "0.0", "-1", "nan", "inf"),
        ("0.001", "2.0", "30"),
    ),
    Bounded(
        "POSTERN_BACKEND_READ_TIMEOUT_SECONDS",
        "backend_read_timeout_seconds",
        "api",
        5.0,
        ("0", "0.0", "-1", "nan", "inf"),
        ("0.001", "5.0", "30"),
    ),
    Bounded(
        "POSTERN_BACKEND_POOL_TIMEOUT_SECONDS",
        "backend_pool_timeout_seconds",
        "api",
        1.0,
        ("-1", "-0.5", "nan", "inf"),
        ("0", "0.0", "1.0", "30"),
    ),
    Bounded(
        "POSTERN_DATABASE_CONNECT_TIMEOUT_SECONDS",
        "database_connect_timeout_seconds",
        "api",
        2.0,
        ("0", "0.0", "-1", "nan", "inf"),
        ("0.001", "2.0", "30"),
    ),
    Bounded(
        "POSTERN_DATABASE_COMMAND_TIMEOUT_SECONDS",
        "database_command_timeout_seconds",
        "api",
        3.0,
        ("0", "0.0", "-1", "nan", "inf"),
        ("0.001", "3.0", "30"),
    ),
    Bounded(
        "POSTERN_DATABASE_POOL_TIMEOUT_SECONDS",
        "database_pool_timeout_seconds",
        "api",
        1.0,
        ("-1", "-0.5", "nan", "inf"),
        ("0", "0.0", "1.0", "30"),
    ),
    Bounded(
        "POSTERN_MAX_BODY_BYTES",
        "max_body_bytes",
        "api",
        1_048_576,
        ("0", "-1"),
        ("1", "8192", "1048576"),
    ),
    Bounded(
        "POSTERN_REQUEST_DEADLINE_SECONDS",
        "request_deadline_seconds",
        "api",
        101.0,
        ("0", "0.0", "-1", "nan", "inf"),
        ("0.001", "101.0", "600"),
    ),
    # --- services/confirm --------------------------------------------------
    Bounded(
        "POSTERN_DEVICE_CODE_TTL_SECONDS",
        "device_code_ttl_seconds",
        "confirm",
        900,
        ("0", "1", "29", "-1"),
        (str(MIN_DEVICE_CODE_TTL_SECONDS), "900"),
    ),
    Bounded(
        "POSTERN_DEVICE_POLL_INTERVAL_SECONDS",
        "device_poll_interval_seconds",
        "confirm",
        5,
        ("0", "-1"),
        ("1", "5", "60"),
    ),
    Bounded(
        "POSTERN_USER_CODE_MAX_ATTEMPTS",
        "user_code_max_attempts",
        "confirm",
        3,
        ("0", "-1", "-5"),
        ("1", "3", "10"),
    ),
    Bounded(
        "POSTERN_CONFIRM_MAX_BODY_BYTES",
        "max_body_bytes",
        "confirm",
        65_536,
        ("0", "-1"),
        ("1", "4096", "65536"),
    ),
    Bounded(
        "POSTERN_CONFIRM_TRUSTED_PROXY_HOPS",
        "trusted_proxy_hops",
        "confirm",
        0,
        ("-1",),
        ("0", "1", "4"),
    ),
    Bounded(
        "POSTERN_MAX_DEVICE_CODES",
        "max_device_codes",
        "confirm",
        10_000,
        ("0", "-1"),
        ("1", "10000"),
    ),
    Bounded(
        "POSTERN_MAX_SCOPES_LENGTH",
        "max_scopes_length",
        "confirm",
        512,
        ("0", "1", str(MIN_SCOPES_LENGTH - 1), "-1"),
        (str(MIN_SCOPES_LENGTH), "512"),
    ),
    Bounded(
        "POSTERN_MAX_CLIENT_ID_LENGTH",
        "max_client_id_length",
        "confirm",
        256,
        ("0", "-1"),
        ("1", "256"),
    ),
    Bounded(
        "POSTERN_DATABASE_CONNECT_TIMEOUT_SECONDS",
        "database_connect_timeout_seconds",
        "confirm",
        2.0,
        ("0", "0.0", "-1", "nan", "inf"),
        ("0.001", "2.0", "30"),
    ),
    Bounded(
        "POSTERN_DATABASE_COMMAND_TIMEOUT_SECONDS",
        "database_command_timeout_seconds",
        "confirm",
        3.0,
        ("0", "0.0", "-1", "nan", "inf"),
        ("0.001", "3.0", "30"),
    ),
    Bounded(
        "POSTERN_DATABASE_POOL_TIMEOUT_SECONDS",
        "database_pool_timeout_seconds",
        "confirm",
        1.0,
        ("-1", "-0.5", "nan", "inf"),
        ("0", "0.0", "1.0", "30"),
    ),
    Bounded(
        "POSTERN_CONFIRM_RATE_LIMIT_DEVICE_AUTHORIZATION",
        "rate_limit_device_authorization",
        "confirm",
        60,
        ("0", "-1"),
        ("1", "60"),
    ),
    Bounded(
        "POSTERN_CONFIRM_RATE_LIMIT_TOKEN", "rate_limit_token", "confirm", 300, ("0", "-1"), ("1",)
    ),
    Bounded(
        "POSTERN_CONFIRM_RATE_LIMIT_APPROVE",
        "rate_limit_approve",
        "confirm",
        60,
        ("0", "-1"),
        ("1",),
    ),
    Bounded(
        "POSTERN_CONFIRM_RATE_LIMIT_CHALLENGE_APPROVE",
        "rate_limit_challenge_approve",
        "confirm",
        60,
        ("0", "-1"),
        ("1",),
    ),
    Bounded(
        "POSTERN_CONFIRM_RATE_LIMIT_DEFAULT",
        "rate_limit_default",
        "confirm",
        60,
        ("0", "-1"),
        ("1",),
    ),
)

IDS = [f"{b.service}:{b.name}" for b in BOUNDED]


def _read(bound: Bounded) -> Any:
    """Parse the environment as ``bound``'s service does, and return its field."""
    settings = Settings.from_env() if bound.service == "api" else ConfirmSettings.from_env()
    return getattr(settings, bound.field)


@pytest.fixture(autouse=True)
def _clean_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """Start every case from an environment with none of these set.

    ``tests/conftest.py``'s ``pg_url`` exports ``POSTERN_DATABASE_URL``
    session-wide, and an earlier file in the run may have set any of the
    others, so "unset" has to be made true rather than assumed. Only the
    variables this file is about are cleared; ``POSTERN_DATABASE_URL`` is left
    alone because nothing here reads it.
    """
    for bound in BOUNDED:
        monkeypatch.delenv(bound.name, raising=False)
    monkeypatch.setenv("POSTERN_BACKEND_BASE_URL", BACKEND_BASE_URL)


class TestEveryNumericSettingIsInTheInventory:
    """The gate that makes the table above a contract rather than a snapshot.

    Both ``from_env`` methods are parsed, not grepped: a bare ``int(...)`` or
    ``float(...)`` anywhere inside one is the exact defect this file closes,
    and it re-enters the same way it entered -- someone adds a field and
    copies the line above it.
    """

    @pytest.mark.parametrize("cls", [Settings, ConfirmSettings], ids=["api", "confirm"])
    def test_from_env_makes_no_bare_int_or_float_call(self, cls: type) -> None:
        source = inspect.getsource(cls.from_env.__func__)  # type: ignore[attr-defined]
        tree = ast.parse(inspect.cleandoc(source))
        bare = [
            node.func.id
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id in {"int", "float"}
        ]
        assert bare == [], (
            f"{cls.__name__}.from_env calls {bare} directly; a bare int()/float() "
            "accepts an empty string as a crash and zero as a value. Read it through "
            "postern_core.config instead, and add the variable to BOUNDED."
        )

    @pytest.mark.parametrize("cls", [Settings, ConfirmSettings], ids=["api", "confirm"])
    def test_every_variable_from_env_reads_is_covered_or_deliberately_not(self, cls: type) -> None:
        """Every ``POSTERN_*`` string literal in ``from_env`` is accounted for.

        A variable is either in `BOUNDED` or in ``NOT_NUMERIC`` below, which
        is the honest half of the inventory: a URL, a key id, a path or a
        flag has no range to leave, and giving one a numeric bound would be
        ceremony.
        """
        not_numeric = {
            "POSTERN_BACKEND_BASE_URL",
            "POSTERN_DATABASE_URL",
            "POSTERN_READ_KEY_PEM_PATH",
            "POSTERN_READ_KEY_KID",
            "POSTERN_READ_TOKEN_ISSUER",
            "POSTERN_WRITE_KEY_PEM_PATH",
            "POSTERN_WRITE_KEY_KID",
            "POSTERN_WRITE_TOKEN_ISSUER",
            "POSTERN_JWKS_URI",
            "POSTERN_TOKEN_ISSUER",
            "POSTERN_AUDIENCE",
            "POSTERN_STRICT_HEADERS",
            "POSTERN_DEVICE_VERIFICATION_URI",
            "POSTERN_APP_ASSERTION_JWKS_URI",
            "POSTERN_APP_ASSERTION_ISSUER",
            "POSTERN_APP_ASSERTION_AUDIENCE",
            "POSTERN_DEVICE_KEYS_PATH",
        }
        source = inspect.getsource(cls.from_env.__func__)  # type: ignore[attr-defined]
        tree = ast.parse(inspect.cleandoc(source))
        read = {
            node.value
            for node in ast.walk(tree)
            if isinstance(node, ast.Constant)
            and isinstance(node.value, str)
            and node.value.startswith("POSTERN_")
        }
        covered = {b.name for b in BOUNDED} | not_numeric
        assert read - covered == set(), f"{cls.__name__}.from_env reads unclassified variables"


class TestTheDefaultClearsItsOwnFloor:
    """A floor above the default would refuse an unconfigured service."""

    @pytest.mark.parametrize("bound", BOUNDED, ids=IDS)
    def test_the_unset_value_is_the_dataclass_default(self, bound: Bounded) -> None:
        assert _read(bound) == bound.default

    @pytest.mark.parametrize("bound", BOUNDED, ids=IDS)
    def test_setting_the_default_explicitly_is_accepted(self, bound: Bounded) -> None:
        """An operator who writes the default into their environment is not refused."""
        import os

        os.environ[bound.name] = str(bound.default)
        try:
            assert _read(bound) == bound.default
        finally:
            del os.environ[bound.name]


class TestTheBoundRefusesAtStartupAndNamesTheVariable:
    """The refusal has to say which line to edit.

    Same posture as `services/confirm/settings.py`'s `_positive_int` and
    `_device_code_ttl`: the failure lands when the app is assembled, and the
    message carries the variable, the bound and the value that was set.
    """

    @pytest.mark.parametrize("bound", BOUNDED, ids=IDS)
    def test_each_refused_value_raises_naming_the_variable(self, bound: Bounded) -> None:
        import os

        for raw in bound.refuses:
            os.environ[bound.name] = raw
            try:
                with pytest.raises(ValueError, match=bound.name) as caught:
                    _read(bound)
            finally:
                del os.environ[bound.name]
            assert raw.strip("+") in str(caught.value) or raw in str(caught.value), (
                f"{bound.name}={raw!r} was refused without echoing the value"
            )

    @pytest.mark.parametrize("bound", BOUNDED, ids=IDS)
    def test_each_accepted_value_parses_to_itself(self, bound: Bounded) -> None:
        import os

        for raw in bound.accepts:
            os.environ[bound.name] = raw
            try:
                expected = int(raw) if isinstance(bound.default, int) else float(raw)
                assert _read(bound) == expected
            finally:
                del os.environ[bound.name]

    @pytest.mark.parametrize("bound", BOUNDED, ids=IDS)
    def test_a_non_numeric_value_refuses_naming_the_variable(self, bound: Bounded) -> None:
        import os

        for raw in ("abc", "5s", "one", "  "):
            os.environ[bound.name] = raw
            try:
                with pytest.raises(ValueError, match=bound.name):
                    _read(bound)
            finally:
                del os.environ[bound.name]


class TestAnEmptyStringMeansUnset:
    """``POSTERN_X=`` is this repository's spelling of "leave it alone".

    `services/api/settings.py`'s `from_env` already collapses ``""`` to
    ``None`` for its five string fields and says why; before 2026-09-25 the
    numeric half of the same convention raised ``invalid literal for int()
    with base 10: ''`` instead, naming neither the variable nor the service.
    """

    @pytest.mark.parametrize("bound", BOUNDED, ids=IDS)
    def test_the_empty_string_gives_the_default(self, bound: Bounded) -> None:
        import os

        os.environ[bound.name] = ""
        try:
            assert _read(bound) == bound.default
        finally:
            del os.environ[bound.name]


class TestPositiveIntMessagesAreUnchanged:
    """`_positive_int` moved onto the shared reader; its two strings did not.

    The literals below are what `services/confirm/settings.py` raised before
    the body was replaced. They are written out here rather than imported,
    because a test that read the message from the code it is checking would
    pass whatever the code said.
    """

    NON_NUMERIC = (
        "POSTERN_CONFIRM_RATE_LIMIT_TOKEN must be a positive integer, got 'abc'. "
        "It is a per-minute request count; there is no value that disables the limit."
    )
    BELOW = (
        "POSTERN_CONFIRM_RATE_LIMIT_TOKEN must be a positive integer, got 0. "
        "It is a per-minute request count; there is no value that disables the limit."
    )

    def test_the_non_numeric_message_is_byte_identical(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("POSTERN_CONFIRM_RATE_LIMIT_TOKEN", "abc")
        with pytest.raises(ValueError) as caught:
            ConfirmSettings.from_env()
        assert str(caught.value) == self.NON_NUMERIC

    def test_the_below_floor_message_is_byte_identical(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("POSTERN_CONFIRM_RATE_LIMIT_TOKEN", "0")
        with pytest.raises(ValueError) as caught:
            ConfirmSettings.from_env()
        assert str(caught.value) == self.BELOW


class TestTheScopesFloorIsDerivedAndNotPicked:
    """`MIN_SCOPES_LENGTH` is the one length here that comes from a measurement.

    It is the length of the string `services/confirm/device_auth.py`
    substitutes for a caller that sends no ``scopes``. If that literal
    changes, this fails rather than the floor quietly becoming wrong, which is
    the arrangement tests/test_device_grant.py::TestTheFloorIsDerivedAndNotPicked
    already has for `MIN_DEVICE_CODE_TTL_SECONDS`.
    """

    def test_the_floor_is_the_length_of_the_substituted_default(self) -> None:
        assert MIN_SCOPES_LENGTH == len(DEFAULT_DEVICE_SCOPES)
        assert MIN_SCOPES_LENGTH == 42

    def test_the_handler_substitutes_exactly_that_string(self) -> None:
        """Read off the handler, so moving the literal back inline fails here."""
        source = Path("services/confirm/device_auth.py").read_text(encoding="utf-8")
        assert 'body.get("scopes", DEFAULT_DEVICE_SCOPES)' in source

    def test_a_ceiling_below_the_floor_would_refuse_the_endpoints_own_default(self) -> None:
        """Which is what makes the floor a bound and not a preference."""
        assert len(DEFAULT_DEVICE_SCOPES) > MIN_SCOPES_LENGTH - 1
        assert ConfirmSettings().max_scopes_length >= MIN_SCOPES_LENGTH


class TestTheBodyLimitFloorIsNotTheAuditCap:
    """8,192 is the bottom of the USEFUL interval, not of the representable one.

    `services/confirm/settings.py`'s comment on ``max_body_bytes`` derives
    `postern_core/store/audit.py`'s `MAX_ARGUMENTS_BYTES` as the point below
    which that column's own cap stops being reachable from any request. That
    is a reason not to go there, not a reason the service cannot run there --
    every legitimate body on this path measures under 300 bytes, and
    tests/test_confirm_body_limit.py already configures 4,096 deliberately.
    Pinning the distinction so a later reader does not "tighten" the floor to
    8,192 and break a working configuration.
    """

    def test_a_limit_below_the_audit_cap_still_parses(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("POSTERN_CONFIRM_MAX_BODY_BYTES", str(MAX_ARGUMENTS_BYTES // 2))
        assert ConfirmSettings.from_env().max_body_bytes == MAX_ARGUMENTS_BYTES // 2

    def test_zero_does_not(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("POSTERN_CONFIRM_MAX_BODY_BYTES", "0")
        with pytest.raises(ValueError, match="POSTERN_CONFIRM_MAX_BODY_BYTES"):
            ConfirmSettings.from_env()


class TestThePoolTimeoutsKeepAcceptingZero:
    """The asymmetry, pinned, because it will look like an oversight.

    Measured 2026-09-25: a pool timeout of zero serves an ordinary request
    200, because it bounds the wait for a free connection and an unsaturated
    pool has no wait to bound. Under saturation it sheds instead of queueing,
    which is a bulkhead an operator may want. The three phases that refuse
    zero fail EVERY request at zero. Refusing zero here would change
    behaviour for a configuration that works.
    """

    @pytest.mark.parametrize(
        "name",
        [
            "POSTERN_BACKEND_POOL_TIMEOUT_SECONDS",
            "POSTERN_DATABASE_POOL_TIMEOUT_SECONDS",
        ],
    )
    def test_zero_is_accepted(self, monkeypatch: pytest.MonkeyPatch, name: str) -> None:
        monkeypatch.setenv(name, "0")
        assert Settings.from_env()
        assert ConfirmSettings.from_env()

    @pytest.mark.parametrize(
        "name",
        [
            "POSTERN_BACKEND_CONNECT_TIMEOUT_SECONDS",
            "POSTERN_BACKEND_READ_TIMEOUT_SECONDS",
            "POSTERN_BACKEND_WRITE_TIMEOUT_SECONDS",
            "POSTERN_DATABASE_CONNECT_TIMEOUT_SECONDS",
            "POSTERN_DATABASE_COMMAND_TIMEOUT_SECONDS",
            "POSTERN_REQUEST_DEADLINE_SECONDS",
        ],
    )
    def test_zero_is_refused_on_every_other_deadline(
        self, monkeypatch: pytest.MonkeyPatch, name: str
    ) -> None:
        monkeypatch.setenv(name, "0")
        with pytest.raises(ValueError, match=name):
            Settings.from_env()


class TestNonFiniteFloats:
    """``nan`` passes ``<= 0`` and ``< 0`` alike, so it needs its own check."""

    def test_nan_is_neither_above_nor_below_any_bound(self) -> None:
        assert not (float("nan") <= 0)
        assert not (float("nan") < 0)

    @pytest.mark.parametrize("raw", ["nan", "inf", "Infinity", "-inf", "1e400"])
    def test_every_non_finite_spelling_is_refused(
        self, monkeypatch: pytest.MonkeyPatch, raw: str
    ) -> None:
        monkeypatch.setenv("POSTERN_REQUEST_DEADLINE_SECONDS", raw)
        with pytest.raises(ValueError, match="POSTERN_REQUEST_DEADLINE_SECONDS"):
            Settings.from_env()


class TestTheReadersThemselves:
    """`postern_core/config.py`'s two functions, away from any settings class."""

    def test_an_unset_variable_returns_the_default(self) -> None:
        assert int_from_env("POSTERN_NOT_SET_ANYWHERE", 7, minimum=1, because="x.") == 7
        assert float_from_env("POSTERN_NOT_SET_ANYWHERE", 1.5, minimum=0, because="x.") == 1.5

    def test_the_bound_phrase_follows_the_minimum(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """So that ``minimum=1`` reads as English and not as arithmetic."""
        monkeypatch.setenv("POSTERN_PROBE", "-1")
        with pytest.raises(ValueError, match="must be a positive integer"):
            int_from_env("POSTERN_PROBE", 1, minimum=1, because="x.")
        with pytest.raises(ValueError, match="must be zero or a positive integer"):
            int_from_env("POSTERN_PROBE", 0, minimum=0, because="x.")
        with pytest.raises(ValueError, match="must be an integer of at least 30"):
            int_from_env("POSTERN_PROBE", 900, minimum=30, because="x.")

    def test_the_reason_travels_with_the_refusal(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("POSTERN_PROBE", "0")
        with pytest.raises(ValueError, match="because the store would be full"):
            int_from_env("POSTERN_PROBE", 1, minimum=1, because="because the store would be full.")

    def test_an_exclusive_minimum_refuses_the_minimum_itself(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("POSTERN_PROBE", "0")
        with pytest.raises(ValueError, match="greater than zero"):
            float_from_env("POSTERN_PROBE", 1.0, minimum=0, exclusive=True, because="x.")
        assert float_from_env("POSTERN_PROBE", 1.0, minimum=0, because="x.") == 0.0

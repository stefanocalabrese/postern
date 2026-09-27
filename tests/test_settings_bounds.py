"""Every numeric setting both services read refuses what it cannot run on.

THE DEFECT CLASS. `d35bc3a` floored ``POSTERN_DEVICE_CODE_TTL_SECONDS`` and in
doing so surfaced that it was one of many: eighteen more numbers across
`services/api/settings.py` and `services/confirm/settings.py` were read with a
bare ``int()`` or ``float()``, each crashing on an empty string with a message
naming neither the variable nor the service, and each silently accepting zero
or a negative. `postern_core/config.py` carries what the two readers do; this
file carries the inventory and the bound each variable got.

A SECOND SEAM, added one commit later. Two more numbers were read with a
bare ``int()`` and were not in either ``from_env``:
``POSTERN_REDIS_SESSION_TTL`` and ``POSTERN_REDIS_DEVICE_CODE_TTL``, which
`postern_core.risk.session`'s `RedisSessionStore` and
`postern_core.auth.device_codes`'s `RedisDeviceCodeStore` read in their own
constructors. `STORE_BOUNDED` is their inventory, and
`TestNoBareNumericEnvironmentReadRemains` is the sweep that would have found
them: it parses every module under ``packages`` and ``services`` rather than
the two methods a reader already knows to look at.

A THIRD SEAM, and it is the one the first two structurally cannot reach.
Both sweeps above key on what a value is USED as -- wrapped in ``int()``,
compared against ``"true"`` -- and a consumer can sit any distance from the
read. Measured on 2026-09-27 against planted shapes: ``raw =
os.environ.get(X)`` followed by ``int(raw)`` on the next line escapes the
numeric rule completely, and it is the way a careless numeric read is most
likely to be written. So the third rule keys on the one thing every spelling
shares, the variable's NAME at the read site. The swept tree names 55
``POSTERN_*`` variables in two disjoint populations: 18 read directly, all of
them strings, listed in `READ_AS_STRING`; and 37 handed to a reader, which are
`BOUNDED`'s 32, `STORE_BOUNDED`'s 2 and `FLAGS`' 3. Nothing is in both,
nothing is in neither, and
`TestEveryEnvironmentReadNamesAnInventoriedVariable` re-derives that from the
tree on every run rather than trusting these numbers.

WHAT THE INVENTORY BELOW IS FOR. `BOUNDED` is the whole set, one record per
variable, and every test here is parametrized over it. A new numeric setting
that is added to a ``from_env`` and not to this tuple fails
`TestEveryNumericSettingIsInTheInventory`, which walks the two ``from_env``
methods rather than trusting anyone to remember.

THE SWEEPS HAD NO POSITIVE CONTROL UNTIL 2026-09-27, which mattered more than
any single gap in them. Every rule here asserts ``offenders == []``, so a
predicate that detected nothing passed exactly as a clean tree does. Measured:
with `_reads_the_environment` replaced by ``return False``, both repo-walking
rules still reported green. `SHAPES` is the fix -- 34 planted spellings, each
naming the exact set of rules that must report it -- and blinding the same
predicate now fails 30 of the 30 rows that expect a report.

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
import functools
import inspect
from pathlib import Path
from typing import Any

import pytest
from postern_core.auth.device_codes import (
    MIN_DEVICE_CODE_TTL_SECONDS as CORE_MIN_DEVICE_CODE_TTL_SECONDS,
)
from postern_core.config import (
    BOOL_FALSE,
    BOOL_TRUE,
    MIN_REPRESENTABLE_TTL_SECONDS,
    float_from_env,
    int_from_env,
)
from postern_core.risk.session import DEFAULT_SESSION_TTL_SECONDS, MIN_SESSION_TTL_SECONDS
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
    # THE ONE PAIR WHERE THE TWO SERVICES DISAGREE ON THE NUMBER, so unlike
    # the three deadlines above they are four variables and not two. The
    # confirm half carries the POSTERN_CONFIRM_ prefix this file already
    # records for `max_body_bytes` and `trusted_proxy_hops`, for the same
    # reason: one env file setting a read path's burst must not move the
    # write path's ceiling as a side effect.
    #
    # The floors differ between the pair, and neither is "reject zero by
    # habit". A `pool_size` of 0 is SQLAlchemy's spelling of "unlimited", so
    # its floor is 1; a `max_overflow` of 0 is a legitimate "no burst" and it
    # is -1 that means unlimited, so its floor is 0. Measured against
    # postgres:17-alpine on 2026-09-26: an engine at either off switch held
    # 25 connections at once against a ceiling that read as one.
    Bounded(
        "POSTERN_DATABASE_POOL_SIZE",
        "database_pool_size",
        "api",
        5,
        ("0", "-1"),
        ("1", "5", "20"),
    ),
    Bounded(
        "POSTERN_DATABASE_MAX_OVERFLOW",
        "database_max_overflow",
        "api",
        10,
        ("-1", "-5"),
        ("0", "10", "50"),
    ),
    # THE THIRD CONNECTION NUMBER, and the only one with no counterpart on the
    # write path: `services/confirm` shares the shape but not this setting,
    # and `docs/user-guide/getting-started.md` records that as owed rather
    # than as a difference of design.
    #
    # ITS FLOOR IS ONE AND ITS ZERO IS NOT AN OFF SWITCH OF THE OTHER KIND.
    # `pool_size=0` and `max_overflow=-1` above are refused because SQLAlchemy
    # reads them as "unlimited"; zero here is a plain absence -- no second
    # engine -- which is `Database`'s own default and what every direct
    # construction in this repository gets. It is floored at one anyway,
    # because reaching it from the environment means a deployment choosing to
    # lose the audit row for every call a saturated pool refuses, which is the
    # silence the reserve exists to end.
    Bounded(
        "POSTERN_DATABASE_AUDIT_RESERVE_SIZE",
        "database_audit_reserve_size",
        "api",
        1,
        ("0", "-1"),
        ("1", "2", "5"),
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
        "POSTERN_CONFIRM_DATABASE_POOL_SIZE",
        "database_pool_size",
        "confirm",
        5,
        ("0", "-1"),
        ("1", "5", "20"),
    ),
    Bounded(
        "POSTERN_CONFIRM_DATABASE_MAX_OVERFLOW",
        "database_max_overflow",
        "confirm",
        5,
        ("-1", "-5"),
        ("0", "5", "50"),
    ),
    # THE WRITE PATH'S RESERVE, the counterpart to the read path's and with the
    # same floor of one. What differs is not the bound but WHICH rows it
    # serves: `services/confirm/audit.py` routes both COMPLETION writes through
    # the reserve and deliberately leaves `ApprovalAudit._write_entry_row` on
    # the pool, so a saturated replica stops before the backend write instead of
    # being carried past it. That asymmetry is a property of the writer, not of
    # this number, and `tests/test_audit_reserve.py` is where it is measured.
    Bounded(
        "POSTERN_CONFIRM_DATABASE_AUDIT_RESERVE_SIZE",
        "database_audit_reserve_size",
        "confirm",
        1,
        ("0", "-1"),
        ("1", "2", "5"),
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
    # The per-CUSTOMER pair, read through the same `_positive_int` as the five
    # above so both families raise identical messages for identical mistakes.
    # Their unit is the verified assertion `sub` rather than a client address
    # bucket; `services/confirm/customer_rate_limit.py` carries the working
    # behind the default of ten.
    Bounded(
        "POSTERN_CONFIRM_CUSTOMER_RATE_LIMIT_APPROVE",
        "customer_rate_limit_approve",
        "confirm",
        10,
        ("0", "-1"),
        ("1",),
    ),
    Bounded(
        "POSTERN_CONFIRM_CUSTOMER_RATE_LIMIT_CHALLENGE_APPROVE",
        "customer_rate_limit_challenge_approve",
        "confirm",
        10,
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


# ---------------------------------------------------------------------------
# The two numbers postern_core's Redis stores read for themselves.
# ---------------------------------------------------------------------------

#: Port 1 is reserved and nothing in this suite listens there. Never dialled:
#: ``redis.asyncio.from_url`` opens no connection, so every assertion below is
#: about what ``__init__`` parsed, which happens before any socket would. The
#: stores that DO need a server are in tests/test_redis_backed_stores.py.
UNREACHABLE_REDIS_URL = "redis://127.0.0.1:1/0"


@dataclasses.dataclass(frozen=True)
class StoreBounded:
    """One environment variable a store constructor reads, and its bound.

    Separate from `Bounded` above because there is no settings dataclass and
    no ``from_env`` behind these two: `postern_core.risk.session`'s
    `RedisSessionStore` and `postern_core.auth.device_codes`'s
    `RedisDeviceCodeStore` read their own variable in ``__init__``, which is
    exactly why they were missed when the nineteen above were bounded.
    """

    name: str
    parameter: str
    attribute: str
    default: int
    minimum: int
    refuses: tuple[str, ...]
    accepts: tuple[str, ...]

    def build(self, **kwargs: Any) -> Any:
        """Construct the store this variable belongs to."""
        from postern_core.auth.device_codes import RedisDeviceCodeStore
        from postern_core.risk.session import RedisSessionStore

        cls = RedisSessionStore if self.parameter == "ttl" else RedisDeviceCodeStore
        return cls(url=UNREACHABLE_REDIS_URL, key_prefix="bounds:", **kwargs)


STORE_BOUNDED: tuple[StoreBounded, ...] = (
    StoreBounded(
        name="POSTERN_REDIS_DEVICE_CODE_TTL",
        parameter="default_ttl",
        attribute="_default_ttl",
        default=900,
        minimum=MIN_DEVICE_CODE_TTL_SECONDS,
        # 1 and 2 are refused although the store can represent 2: this
        # variable shares its floor with POSTERN_DEVICE_CODE_TTL_SECONDS,
        # because both set the lifetime of the same device code.
        refuses=("0", "-1", "1", "2", "5", "29", "-900"),
        accepts=("30", "900", "3600"),
    ),
    StoreBounded(
        name="POSTERN_REDIS_SESSION_TTL",
        parameter="ttl",
        attribute="_ttl",
        default=DEFAULT_SESSION_TTL_SECONDS,
        minimum=MIN_SESSION_TTL_SECONDS,
        refuses=("0", "-1", "-1800"),
        accepts=("1", "60", "1800", "7200"),
    ),
)

STORE_IDS = [b.name for b in STORE_BOUNDED]


@pytest.fixture(autouse=True)
def _clean_store_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    for bound in STORE_BOUNDED:
        monkeypatch.delenv(bound.name, raising=False)


class TestTheStoreVariablesAreBoundedToo:
    """The same three properties the nineteen above got, at a different seam."""

    @pytest.mark.parametrize("bound", STORE_BOUNDED, ids=STORE_IDS)
    def test_an_unset_or_empty_variable_gives_the_documented_default(
        self, bound: StoreBounded, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        assert getattr(bound.build(), bound.attribute) == bound.default
        monkeypatch.setenv(bound.name, "")
        assert getattr(bound.build(), bound.attribute) == bound.default

    @pytest.mark.parametrize("bound", STORE_BOUNDED, ids=STORE_IDS)
    def test_the_default_clears_its_own_floor(self, bound: StoreBounded) -> None:
        assert bound.default >= bound.minimum

    @pytest.mark.parametrize("bound", STORE_BOUNDED, ids=STORE_IDS)
    def test_each_refused_value_names_the_variable_and_echoes_the_value(
        self, bound: StoreBounded, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        for raw in bound.refuses:
            monkeypatch.setenv(bound.name, raw)
            with pytest.raises(ValueError, match=bound.name) as caught:
                bound.build()
            assert raw in str(caught.value), f"{bound.name}={raw!r} refused without echoing it"

    @pytest.mark.parametrize("bound", STORE_BOUNDED, ids=STORE_IDS)
    def test_each_accepted_value_parses_to_itself(
        self, bound: StoreBounded, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        for raw in bound.accepts:
            monkeypatch.setenv(bound.name, raw)
            assert getattr(bound.build(), bound.attribute) == int(raw)

    @pytest.mark.parametrize("bound", STORE_BOUNDED, ids=STORE_IDS)
    def test_a_non_numeric_value_refuses_naming_the_variable(
        self, bound: StoreBounded, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        for raw in ("abc", "30s", "1.5", "  "):
            monkeypatch.setenv(bound.name, raw)
            with pytest.raises(ValueError, match=bound.name):
                bound.build()


class TestTheFalsyZeroPassthrough:
    """``ttl or int(os.environ.get(...))`` discarded the number the caller passed.

    Zero is falsy, so `RedisSessionStore` built with ``ttl=0`` and
    `RedisDeviceCodeStore` built with ``default_ttl=0`` silently used the
    environment's value instead, or the default when the variable was unset.
    Measured before the fix with the two variables set to 888 and 777:
    ``_ttl`` came back 888 and ``_default_ttl`` 777. That is the same "a
    value you set does nothing" failure the bounds above exist to prevent,
    one argument in from the environment.

    IT IS REFUSED RATHER THAN HONOURED, and `postern_core/config.py`'s
    `int_arg_or_env` carries the reasoning: at ``_ttl = 0`` a risk context is
    deleted by the very next ``load``, so no ZT-5 budget ever accumulates,
    and at ``_default_ttl = 0`` every device code is written nowhere.
    """

    @pytest.mark.parametrize("bound", STORE_BOUNDED, ids=STORE_IDS)
    def test_zero_no_longer_reaches_the_environment(
        self, bound: StoreBounded, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(bound.name, "1800")
        with pytest.raises(ValueError, match=bound.parameter) as caught:
            bound.build(**{bound.parameter: 0})
        assert "1800" not in str(caught.value), "the environment's value was never consulted"

    @pytest.mark.parametrize("bound", STORE_BOUNDED, ids=STORE_IDS)
    def test_a_negative_argument_is_refused_the_same_way(self, bound: StoreBounded) -> None:
        with pytest.raises(ValueError, match=bound.parameter):
            bound.build(**{bound.parameter: -5})

    @pytest.mark.parametrize("bound", STORE_BOUNDED, ids=STORE_IDS)
    def test_the_refusal_says_how_to_ask_for_the_environment(self, bound: StoreBounded) -> None:
        """``None`` is the spelling, and a caller who wrote ``0`` meant zero."""
        with pytest.raises(ValueError, match="Pass None") as caught:
            bound.build(**{bound.parameter: 0})
        assert bound.name in str(caught.value)

    @pytest.mark.parametrize("bound", STORE_BOUNDED, ids=STORE_IDS)
    def test_a_positive_argument_still_wins_over_the_environment(
        self, bound: StoreBounded, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Unchanged, including the laziness: a set variable is not even parsed.

        A store built with its own number never read the variable under
        ``or``, because ``or`` short-circuits. It still does not, which is
        what keeps tests/test_redis_backed_stores.py's harness -- and any
        caller passing its own number -- working in an environment that holds
        a value this store would otherwise refuse.
        """
        monkeypatch.setenv(bound.name, "not-a-number")
        assert getattr(bound.build(**{bound.parameter: 600}), bound.attribute) == 600

    @pytest.mark.parametrize("bound", STORE_BOUNDED, ids=STORE_IDS)
    def test_the_argument_floor_is_representability_and_not_the_operator_floor(
        self, bound: StoreBounded
    ) -> None:
        """One second in code, whatever the variable refuses.

        For the session store the two coincide. For the device code store
        they do not, on purpose: ``create_device_code``'s ``expires_in``
        takes 2 (tests/test_redis_backed_stores.py::SHORTEST_STORED_TTL) and
        ``default_ttl`` is only the value it falls back to, so a fallback
        floored at 30 would refuse in code what the same store accepts one
        argument later.
        """
        assert getattr(bound.build(**{bound.parameter: 1}), bound.attribute) == 1


class TestTheDeviceCodeFloorIsOneNumberAndNotTwo:
    """Two variables set the lifetime of the same device code.

    ``POSTERN_DEVICE_CODE_TTL_SECONDS`` reaches it as ``create_device_code``'s
    ``expires_in``; ``POSTERN_REDIS_DEVICE_CODE_TTL`` reaches the same
    argument through ``_default_ttl`` when no ``expires_in`` is passed. The
    first was floored at 30 seconds on 2026-09-25 and the second was left a
    bare ``int()`` the same day, so an operator could set one safely and the
    other not. A second literal would let that reopen in silence.
    """

    def test_the_service_carries_no_second_literal(self) -> None:
        """Parsed, not compared.

        ``assert a is b`` would pass against two independent ``30``s, because
        CPython caches small integers -- the first draft of this test did
        exactly that and survived the mutation that split the constant in
        two. What has to be false is that
        `services/confirm/settings.py` assigns a NUMBER to this name at all.
        """
        source = Path(inspect.getfile(ConfirmSettings)).read_text(encoding="utf-8")
        assigned = [
            node.value
            for node in ast.walk(ast.parse(source))
            if isinstance(node, ast.Assign)
            and any(
                isinstance(t, ast.Name) and t.id == "MIN_DEVICE_CODE_TTL_SECONDS"
                for t in node.targets
            )
        ]
        assert len(assigned) == 1, "the name is assigned once, as a re-export"
        assert isinstance(assigned[0], ast.Name), (
            f"services/confirm/settings.py assigns {ast.dump(assigned[0])} to "
            "MIN_DEVICE_CODE_TTL_SECONDS. A second literal is free to drift away from "
            "postern_core.auth.device_codes', and then one of the two variables that set "
            "a device code's lifetime is floored and the other is not."
        )

    def test_the_two_names_hold_the_same_number(self) -> None:
        assert MIN_DEVICE_CODE_TTL_SECONDS == CORE_MIN_DEVICE_CODE_TTL_SECONDS == 30

    def test_the_session_floor_claims_only_representability(self) -> None:
        """No derivation is claimed for it, and the constant says so."""
        assert MIN_SESSION_TTL_SECONDS == MIN_REPRESENTABLE_TTL_SECONDS == 1


# ---------------------------------------------------------------------------
# The sweep's machinery. One parse of the tree, three rules over it.
# ---------------------------------------------------------------------------

#: Where the sweep looks.
#:
#: ``migrations`` was added on 2026-09-27, and it is a correction rather than a
#: widening: the two rules above scoped themselves to ``packages`` and
#: ``services`` on the stated ground that they are "the only code that runs in a
#: container", and that is not true of `migrations/env.py`, which reads
#: ``POSTERN_DATABASE_URL`` and runs under ``alembic upgrade`` in exactly the
#: container the operator checklist describes. ``tools`` and ``stub`` stay out
#: and the reason is now the honest one: they are developer code an operator
#: never runs. ``stub/backend.py`` does read two variables, and that is the
#: local-development stub whose whole purpose is to stand in for a backend.
SWEPT_ROOTS = ("packages", "services", "migrations")

#: The four attributes of ``os`` that reach the process environment.
#:
#: ``environb`` and ``getenvb`` were absent until 2026-09-27, which made
#: ``int(os.environb[b"POSTERN_X"])`` invisible to the numeric rule. They are
#: the bytes-keyed mapping over the same environment, so leaving them out was
#: a hole and not a scope decision.
_ENV_ACCESSORS = frozenset({"environ", "environb", "getenv", "getenvb"})

#: Every reader that takes a variable's name, and where in the call it takes it.
#:
#: ``None`` means keyword-only: `postern_core/config.py`'s `int_arg_or_env`
#: takes ``passed`` first and everything after it is keyword-only, so its name
#: can only ever arrive as ``name=``.
_READER_NAME_POSITION: dict[str, int | None] = {
    "int_from_env": 0,
    "float_from_env": 0,
    "bool_from_env": 0,
    "int_arg_or_env": None,
    "_positive_int": 0,
    "_device_code_ttl": 0,
}

#: The functions allowed to read a variable whose name they were handed.
#:
#: It is the same six names as `_READER_NAME_POSITION` and that is not a
#: coincidence: a reader is by definition the thing that takes a name, so the
#: set of functions that may read a name they did not write down is exactly the
#: set of readers. A seventh would make every variable it reads invisible to
#: the two inventories below, which is the objection
#: `postern_core/config.py`'s own docstring raises against "a third validation
#: style in the tree".
GENERIC_READERS = frozenset(_READER_NAME_POSITION)

#: Every variable the swept tree reads DIRECTLY, without a bounded reader.
#:
#: ALL EIGHTEEN ARE STRINGS, and that is the invariant this list exists to
#: hold rather than an observation about today's tree. A number belongs in
#: `BOUNDED` or `STORE_BOUNDED` and is read through `int_from_env` or
#: `float_from_env`; a flag belongs in `FLAGS` and is read through
#: `bool_from_env`. Only a value with no bound to state -- a URL, a filesystem
#: path, a key id, an issuer, an audience, a Redis key prefix -- is read
#: straight out of the environment, and then its name belongs here.
#:
#: WHAT ADDING A NAME HERE COSTS THE AUTHOR, which is the whole mechanism: it
#: is a line in a diff, in a list whose docstring says flags and numbers do not
#: belong in it. The rule cannot stop someone writing that line. It can stop
#: them adding a flag without anyone seeing them do it.
READ_AS_STRING: frozenset[str] = frozenset(
    {
        "POSTERN_APP_ASSERTION_AUDIENCE",
        "POSTERN_APP_ASSERTION_ISSUER",
        "POSTERN_APP_ASSERTION_JWKS_URI",
        "POSTERN_AUDIENCE",
        "POSTERN_BACKEND_BASE_URL",
        "POSTERN_DATABASE_URL",
        "POSTERN_DEVICE_KEYS_PATH",
        "POSTERN_DEVICE_VERIFICATION_URI",
        "POSTERN_JWKS_URI",
        "POSTERN_READ_KEY_KID",
        "POSTERN_READ_KEY_PEM_PATH",
        "POSTERN_READ_TOKEN_ISSUER",
        "POSTERN_REDIS_KEY_PREFIX",
        "POSTERN_REDIS_URL",
        "POSTERN_TOKEN_ISSUER",
        "POSTERN_WRITE_KEY_KID",
        "POSTERN_WRITE_KEY_PEM_PATH",
        "POSTERN_WRITE_TOKEN_ISSUER",
    }
)

#: The three flags, each read through `postern_core/config.py`'s `bool_from_env`.
#:
#: They carry no bound and so no `Bounded` record, which is why they are a bare
#: set of names: what `bool_from_env` enforces is an ACCEPTING SET, the same one
#: for every flag, and it is pinned in `tests/test_require_redis_guard.py`
#: rather than per variable. All three were read by hand until 2026-09-26, and
#: ``POSTERN_REQUIRE_PEM_KEY=true`` meant "do not require a PEM key".
FLAGS: frozenset[str] = frozenset(
    {
        "POSTERN_REQUIRE_PEM_KEY",
        "POSTERN_REQUIRE_REDIS",
        "POSTERN_STRICT_HEADERS",
    }
)

#: The names in the two numeric inventories above, for the membership test.
BOUNDED_NAMES: frozenset[str] = frozenset(bound.name for bound in BOUNDED)
STORE_BOUNDED_NAMES: frozenset[str] = frozenset(bound.name for bound in STORE_BOUNDED)


def _reads_the_environment(node: ast.AST, aliases: frozenset[str] = _ENV_ACCESSORS) -> bool:
    """``os.environ``, ``os.environ.get``, ``os.getenv``, and bare re-exports.

    ``aliases`` carries what ``from os import environ as E`` bound in the
    module being parsed, so a rename does not hide a read. It defaults to the
    plain spellings, which is what a caller with no module in hand can know.
    """
    if isinstance(node, ast.Attribute):
        return node.attr in _ENV_ACCESSORS
    return isinstance(node, ast.Name) and node.id in aliases


@dataclasses.dataclass(frozen=True)
class EnvSite:
    """One place a module reaches the environment, and what it named there.

    ``shape`` is ``"direct"`` for a read straight off the mapping,
    ``"reader"`` for a name handed to one of `GENERIC_READERS`, and
    ``"unnamed"`` for everything else that touches the environment -- a bulk
    copy, a write, or the mapping passed somewhere whole. ``name`` is ``None``
    when the sweep could not resolve one, which is an offence outside a
    generic reader and the normal case inside one.
    """

    where: str
    shape: str
    name: str | None
    enclosing: str | None


@functools.cache
def _parse(source: str) -> ast.Module:
    """One parse per source text, shared by all three rules."""
    return ast.parse(source)


@functools.cache
def _swept_modules() -> tuple[tuple[str, str], ...]:
    """Every shipping module, as ``(path, source)``, read once per session."""
    repo = Path(__file__).resolve().parent.parent
    return tuple(
        (str(path.relative_to(repo)), path.read_text(encoding="utf-8"))
        for root in SWEPT_ROOTS
        for path in sorted((repo / root).rglob("*.py"))
    )


def _environment_aliases(tree: ast.Module) -> frozenset[str]:
    """What this module can call the environment, imports included."""
    names = set(_ENV_ACCESSORS)
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module in {"os", "posix", "nt"}:
            names.update(
                alias.asname or alias.name for alias in node.names if alias.name in _ENV_ACCESSORS
            )
    return frozenset(names)


def _module_string_constants(tree: ast.Module) -> dict[str, str]:
    """Module-level ``NAME = "literal"`` bindings, so an indirect read resolves.

    `postern_core/config.py` reads ``os.environ.get(REDIS_URL_ENV)`` and hands
    ``REQUIRE_REDIS_ENV`` to `bool_from_env`. Both are module constants naming
    a variable, and a sweep that only understood string literals would call
    both unresolvable and fail the build on the module that does this right.
    """
    constants: dict[str, str] = {}
    for node in tree.body:
        targets: list[ast.expr] = []
        if isinstance(node, ast.Assign):
            targets = list(node.targets)
        elif isinstance(node, ast.AnnAssign):
            targets = [node.target]
        value = node.value if isinstance(node, ast.Assign | ast.AnnAssign) else None
        if not isinstance(value, ast.Constant) or not isinstance(value.value, str):
            continue
        for target in targets:
            if isinstance(target, ast.Name):
                constants[target.id] = value.value
    return constants


def _enclosing_functions(tree: ast.Module) -> dict[int, str | None]:
    """The innermost ``def`` around each node, or ``None`` at module level."""
    holder: dict[int, str | None] = {id(tree): None}

    def visit(node: ast.AST, current: str | None) -> None:
        for child in ast.iter_child_nodes(node):
            inner = current
            if isinstance(child, ast.FunctionDef | ast.AsyncFunctionDef):
                inner = child.name
            holder[id(child)] = inner
            visit(child, inner)

    visit(tree, None)
    return holder


def _called_function_name(func: ast.expr) -> str | None:
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return None


def env_sites(where: str, source: str) -> tuple[EnvSite, ...]:
    """Every environment site in one module, classified.

    THE CLASSIFICATION IS EXHAUSTIVE BY CONSTRUCTION, which is the property
    that makes the promise "a new read cannot hide" true rather than hopeful.
    Each recognised shape consumes the accessor node it read; every accessor
    node left unconsumed at the end becomes an ``"unnamed"`` site. So a
    spelling nobody anticipated is not silently skipped -- it lands in the one
    bucket the rules refuse outright.
    """
    tree = _parse(source)
    aliases = _environment_aliases(tree)
    constants = _module_string_constants(tree)
    enclosing = _enclosing_functions(tree)
    sites: list[EnvSite] = []
    consumed: set[int] = set()

    def resolve(node: ast.expr | None) -> str | None:
        if isinstance(node, ast.Constant):
            if isinstance(node.value, str):
                return node.value
            if isinstance(node.value, bytes):
                return node.value.decode("utf-8", "replace")
        if isinstance(node, ast.Name):
            return constants.get(node.id)
        return None

    def accessor(node: ast.AST) -> bool:
        return _reads_the_environment(node, aliases)

    def record(node: ast.expr, shape: str, name: str | None) -> None:
        sites.append(EnvSite(f"{where}:{node.lineno}", shape, name, enclosing.get(id(node))))

    for node in ast.walk(tree):
        if isinstance(node, ast.Subscript) and accessor(node.value):
            consumed.add(id(node.value))
            record(node, "direct", resolve(node.slice))
            continue
        if not isinstance(node, ast.Call):
            continue
        first = node.args[0] if node.args else None
        if accessor(node.func):  # os.getenv("X")
            consumed.add(id(node.func))
            record(node, "direct", resolve(first))
            continue
        if isinstance(node.func, ast.Attribute) and accessor(node.func.value):
            consumed.add(id(node.func.value))
            if node.func.attr == "get":
                record(node, "direct", resolve(first))
            else:  # copy, pop, setdefault, update, items, ...
                record(node, "unnamed", None)
            continue
        called = _called_function_name(node.func)
        if called in _READER_NAME_POSITION:
            position = _READER_NAME_POSITION[called]
            argument: ast.expr | None = None
            if position is not None and len(node.args) > position:
                argument = node.args[position]
            for keyword in node.keywords:
                if keyword.arg == "name":
                    argument = keyword.value
            record(node, "reader", resolve(argument))

    for node in ast.walk(tree):
        if not isinstance(node, ast.Attribute | ast.Name):
            continue
        if accessor(node) and id(node) not in consumed:
            record(node, "unnamed", None)
    return tuple(sites)


@functools.cache
def _all_env_sites() -> tuple[EnvSite, ...]:
    """Every environment site in the swept tree."""
    return tuple(site for where, source in _swept_modules() for site in env_sites(where, source))


def _numeric_offenders(where: str, source: str) -> list[str]:
    """``int()`` or ``float()`` wrapped straight around an environment read."""
    tree = _parse(source)
    aliases = _environment_aliases(tree)
    offenders: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if not (isinstance(node.func, ast.Name) and node.func.id in {"int", "float"}):
            continue
        if any(_reads_the_environment(inner, aliases) for inner in ast.walk(node)):
            offenders.append(f"{where}:{node.lineno}")
    return offenders


def _boolean_offenders(where: str, source: str) -> list[str]:
    """An environment read tested against a boolean token, or through ``bool()``."""
    tree = _parse(source)
    aliases = _environment_aliases(tree)
    tokens = BOOL_TRUE | BOOL_FALSE
    offenders: list[str] = []

    def is_env_read(node: ast.AST) -> bool:
        return any(_reads_the_environment(inner, aliases) for inner in ast.walk(node))

    def is_boolean_literal(node: ast.AST) -> bool:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value.strip().lower() in tokens
        if isinstance(node, ast.Tuple | ast.List | ast.Set):
            return any(is_boolean_literal(element) for element in node.elts)
        return False

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id == "bool" and is_env_read(node):
                offenders.append(f"{where}:{node.lineno} bool()")
            continue
        if not isinstance(node, ast.Compare):
            continue
        if not any(isinstance(op, ast.Eq | ast.NotEq | ast.In | ast.NotIn) for op in node.ops):
            continue
        sides = [node.left, *node.comparators]
        if any(is_env_read(side) for side in sides) and any(
            is_boolean_literal(side) for side in sides
        ):
            offenders.append(f"{where}:{node.lineno} comparison")
    return offenders


def _inventory_offenders(where: str, source: str) -> list[str]:
    """A variable read under a name no inventory in this file holds."""
    through_a_reader = BOUNDED_NAMES | STORE_BOUNDED_NAMES | FLAGS
    offenders: list[str] = []
    for site in env_sites(where, source):
        if site.name is None:
            if site.enclosing not in GENERIC_READERS:
                offenders.append(f"{site.where} names no variable")
        elif site.shape == "direct" and site.name not in READ_AS_STRING:
            offenders.append(f"{site.where} reads {site.name!r} directly")
        elif site.shape == "reader" and site.name not in through_a_reader:
            offenders.append(f"{site.where} reads {site.name!r} through a reader")
    return offenders


#: The three rules, in the order `SHAPES` below reports them.
_RULES = {
    "numeric": _numeric_offenders,
    "boolean": _boolean_offenders,
    "inventory": _inventory_offenders,
}


class TestNoBareNumericEnvironmentReadRemains:
    """The question this line of work exists to close, asked mechanically.

    `TestEveryNumericSettingIsInTheInventory` above parses the two
    ``from_env`` methods, which is where nineteen of these lived -- and is
    precisely why the two in this file's second half were missed, since they
    are read in a constructor in another package. This walks every module
    that ships instead, so the next one cannot hide by being somewhere new.

    SCOPED TO WHAT SHIPS, which is `SWEPT_ROOTS` and no longer the two
    ``root_packages`` in ``.importlinter``. This docstring justified those two
    as "the only code that runs in a container" and that claim was wrong:
    `migrations/env.py` reads ``POSTERN_DATABASE_URL`` and runs under
    ``alembic upgrade``, in a container, against the operator's real database.
    ``tools`` and ``stub`` are still out, on the narrower ground that an
    operator runs neither.

    WHAT THESE TWO RULES CANNOT SEE, and it is the reason a third one exists
    below: they key on what a value is USED as. A read whose value reaches
    ``int()`` through a local variable escapes both, and so does any consumer
    nobody enumerated. `TestEveryEnvironmentReadNamesAnInventoriedVariable`
    keys on the variable's NAME at the read site instead, and `SHAPES` is the
    table of which rule sees which spelling.
    """

    def test_no_int_or_float_call_wraps_an_environment_read(self) -> None:
        offenders = [
            offender
            for where, source in _swept_modules()
            for offender in _numeric_offenders(where, source)
        ]
        assert offenders == [], (
            f"{offenders} wrap an environment read in a bare int()/float(). That accepts "
            "an empty string as a crash naming neither the variable nor the module, and "
            "zero and negatives in silence. Read it through postern_core.config instead."
        )

    def test_no_environment_read_is_compared_against_a_boolean_token(self) -> None:
        """The same sweep, for flags rather than numbers.

        WHY THIS ARRIVED SECOND. The numeric half above landed on 2026-09-25
        and could not be extended to booleans then, because three flags were
        still reading ``os.environ.get(X) == "1"`` and the check would have
        failed the build on all three. They were converted on 2026-09-26, so
        the objection is gone and the shape is closed the same way: not by
        remembering, but by parsing every module that ships.

        WHAT COUNTS AS A BOOLEAN READ, and the definition is deliberately
        narrow so the rule has no false positives:

        - an environment read compared with ``==`` or ``!=`` against a string
          literal that is one of `BOOL_TRUE` or `BOOL_FALSE`;
        - an environment read tested with ``in`` against a literal collection
          holding one;
        - an environment read wrapped in ``bool()``, which is the subtlest of
          the three: ``bool("0")`` is ``True``, so that spelling turns every
          off value into on.

        Comparing an environment read against a NON-boolean literal is left
        alone, because ``os.environ.get("POSTERN_ENV") == "production"`` is an
        ordinary string test and not a flag. Keying the rule on the literal
        rather than on the comparison is what separates the two.

        WHAT THIS RULE STILL DOES NOT CATCH, and it is no longer the whole
        gap: bare truthiness, ``if os.environ.get(X):``. It is indistinguishable
        at the syntax level from "is this string configured?", which this
        repository does correctly in six places for ``POSTERN_REDIS_URL`` --
        `create_session_store`, `create_revocation_store`,
        `create_device_code_store`, `create_customer_rate_limit_store`,
        `postern_core.auth.revoke_cli` and `config.py`'s
        `enforce_redis_requirement`. A rule that flagged those would be
        switched off within a week, and a check nobody trusts is worse than no
        check.

        THAT REASONING STILL HOLDS AND THE GAP IS CLOSED ANYWAY, by asking a
        different question one class down.
        `TestEveryEnvironmentReadNamesAnInventoriedVariable` never looks at the
        ``if``: it takes the NAME at the read site and requires it to be in an
        inventory. All six of those sites read ``POSTERN_REDIS_URL``, which is
        in `READ_AS_STRING`, so the rule is silent on every one of them and
        stays silent however they are rewritten -- while ``if
        os.environ.get("POSTERN_NEW_FLAG"):`` fails, because the name is in no
        inventory. Two other discriminators were tried first and both failed
        against those same six sites; that class's docstring records what each
        one did.
        """
        offenders = [
            offender
            for where, source in _swept_modules()
            for offender in _boolean_offenders(where, source)
        ]
        assert offenders == [], (
            f"{offenders} read a boolean environment variable by hand. Every spelling "
            "other than the one compared against then means off, silently, which on a "
            "safety switch is the wrong direction: POSTERN_REQUIRE_PEM_KEY=true used to "
            "mean 'do not require a PEM key'. Read it through "
            "postern_core.config.bool_from_env instead."
        )


# ---------------------------------------------------------------------------
# The adversarial table. One row per spelling a careless author might produce.
# ---------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class Shape:
    """One spelling of an environment read, and which rule is meant to see it.

    ``caught_by`` is the EXACT set of rules expected to fire, so a row is a
    two-sided assertion: the named rules must fire and the unnamed ones must
    not. An empty tuple pins a known gap, and the table is therefore the same
    list of gaps this file's docstrings claim, in a form that fails when the
    claim stops being true.
    """

    label: str
    source: str
    caught_by: tuple[str, ...]
    note: str


#: An inventoried name, used wherever a row is about the CONSUMER rules alone.
#: Reading it says nothing about the name, so only the rule under test fires.
_KNOWN = "POSTERN_REDIS_URL"

#: A name in no inventory, used wherever a row is about the NAME rule.
_UNKNOWN = "POSTERN_NEW_FEATURE_FLAG"

SHAPES: tuple[Shape, ...] = (
    # --- what the two consumer rules were built to catch --------------------
    Shape(
        "int() wrapping a read",
        f'import os\nT = int(os.environ.get("{_KNOWN}", "5"))\n',
        ("numeric",),
        "The original defect class. An empty string crashes, zero passes.",
    ),
    Shape(
        "float() wrapping a read",
        f'import os\nT = float(os.environ.get("{_KNOWN}", "5"))\n',
        ("numeric",),
        "Same, plus nan and inf, which no lower bound written as < refuses.",
    ),
    Shape(
        "int() wrapping a subscript",
        f'import os\nT = int(os.environ["{_KNOWN}"])\n',
        ("numeric",),
        "The subscript is a different read and the same defect.",
    ),
    Shape(
        "int() wrapping os.getenv",
        f'import os\nT = int(os.getenv("{_KNOWN}", "5"))\n',
        ("numeric",),
        "getenv is os.environ.get under another name.",
    ),
    Shape(
        'a read == "true"',
        f'import os\nF = os.environ.get("{_KNOWN}") == "true"\n',
        ("boolean",),
        "One spelling means on and the other three silently mean off.",
    ),
    Shape(
        'a read != "0"',
        f'import os\nF = os.environ.get("{_KNOWN}") != "0"\n',
        ("boolean",),
        "The same defect inverted: every misspelling means ON.",
    ),
    Shape(
        'a read in ("1", "true")',
        f'import os\nF = os.environ.get("{_KNOWN}") in ("1", "true")\n',
        ("boolean",),
        "A hand-rolled accepting set, which is what bool_from_env is.",
    ),
    Shape(
        "bool() wrapping a read",
        f'import os\nF = bool(os.environ.get("{_KNOWN}"))\n',
        ("boolean",),
        'The subtlest: bool("0") is True, so every off value reads as on.',
    ),
    # --- what only the name rule sees ---------------------------------------
    Shape(
        "bare truthiness on a new variable",
        f'import os\nif os.environ.get("{_UNKNOWN}"):\n    pass\n',
        ("inventory",),
        "The shape this file called its last hiding place. Caught by name.",
    ),
    Shape(
        "a truthy default",
        f'import os\nif os.environ.get("{_UNKNOWN}", "1"):\n    pass\n',
        ("inventory",),
        "Worse than bare truthiness: the branch is taken when nothing is set.",
    ),
    Shape(
        "is not None",
        f'import os\nF = os.environ.get("{_UNKNOWN}") is not None\n',
        ("inventory",),
        "A presence flag the boolean rule cannot see: Is is not Eq.",
    ),
    Shape(
        "subscript access",
        f'import os\nF = os.environ["{_UNKNOWN}"]\n',
        ("inventory",),
        "No .get, so nothing about the call shape gives it away.",
    ),
    Shape(
        "a read bound to a local, then int()",
        f'import os\nraw = os.environ.get("{_UNKNOWN}")\nT = int(raw)\n',
        ("inventory",),
        "The most natural careless numeric read, and the consumer rule's "
        "worst blind spot: int() and the read are in different statements.",
    ),
    Shape(
        "a read bound to a local, then tested",
        f'import os\nraw = os.environ.get("{_UNKNOWN}")\nif raw:\n    pass\n',
        ("inventory",),
        "One assignment is enough to evade every consumer-keyed rule.",
    ),
    Shape(
        "a walrus in an if",
        f'import os\nif (raw := os.environ.get("{_UNKNOWN}")) is not None:\n    pass\n',
        ("inventory",),
        "Binds and tests in one expression; still a named read.",
    ),
    Shape(
        "a read inside a comprehension",
        f'import os\nF = [v for v in [os.environ.get("{_UNKNOWN}")] if v]\n',
        ("inventory",),
        "Position in the syntax tree never mattered to a name-keyed rule.",
    ),
    Shape(
        "a read inside a ternary",
        f'import os\nF = True if os.environ.get("{_UNKNOWN}") else False\n',
        ("inventory",),
        "Same.",
    ),
    Shape(
        "a module-level read at import time",
        f'import os\nFLAG = os.environ.get("{_UNKNOWN}") == "yes"\n',
        ("boolean", "inventory"),
        "Import time is when this is worst -- no from_env runs, so no bound "
        "applies -- and both rules see it.",
    ),
    Shape(
        "not not, to dodge bool()",
        f'import os\nF = not not os.environ.get("{_UNKNOWN}")\n',
        ("inventory",),
        "Deliberate evasion of the bool() rule, defeated by the name.",
    ),
    Shape(
        "Decimal() instead of int()",
        f'import os\nfrom decimal import Decimal\nT = Decimal(os.environ.get("{_UNKNOWN}"))\n',
        ("inventory",),
        "Any numeric constructor the numeric rule does not enumerate.",
    ),
    Shape(
        "an f-string name",
        'import os\nPART = "FLAG"\nif os.environ.get(f"POSTERN_{PART}"):\n    pass\n',
        ("inventory",),
        "No name to check, and the rule refuses rather than shrugging.",
    ),
    Shape(
        "a concatenated name",
        'import os\nif os.environ.get("POSTERN_" + "NEW"):\n    pass\n',
        ("inventory",),
        "Same: unresolvable outside the six readers is an offence.",
    ),
    Shape(
        "a new generic reader taking a name",
        "import os\n"
        "def _flag(name: str) -> bool:\n"
        "    if os.environ.get(name):\n"
        "        return True\n"
        "    return False\n",
        ("inventory",),
        "A seventh reader would make every variable it reads invisible, so "
        "the six are a closed list and a seventh fails.",
    ),
    Shape(
        "dict(os.environ)",
        f'import os\nE = dict(os.environ)\nF = E.get("{_UNKNOWN}") == "1"\n',
        ("inventory",),
        "A bulk copy names nothing, so nothing downstream can be checked.",
    ),
    Shape(
        "os.environ.copy()",
        f'import os\nE = os.environ.copy()\nT = int(E["{_UNKNOWN}"])\n',
        ("inventory",),
        "Same, through the mapping's own method.",
    ),
    Shape(
        "os.environ.setdefault",
        f'import os\nos.environ.setdefault("{_UNKNOWN}", "1")\n',
        ("inventory",),
        "A WRITE to the process environment, which makes a variable look "
        "configured to every later reader. No shipping module should.",
    ),
    Shape(
        "os.environ passed whole",
        'import os\nimport subprocess\nsubprocess.run(["true"], env=os.environ, check=True)\n',
        ("inventory",),
        "Names nothing. There are none today and a first one owes a reason.",
    ),
    Shape(
        "an aliased import",
        f'from os import environ as E\nif E.get("{_UNKNOWN}"):\n    pass\n',
        ("inventory",),
        "The alias is read off the import, so the rename buys nothing.",
    ),
    Shape(
        "an aliased import wrapped in int()",
        f'from os import environ as E\nT = int(E["{_UNKNOWN}"])\n',
        ("numeric", "inventory"),
        "This shape defeated the numeric rule until the aliases were "
        "followed; it is the one row where widening was load-bearing.",
    ),
    Shape(
        "os.environb",
        f'import os\nT = int(os.environb[b"{_UNKNOWN}"])\n',
        ("numeric", "inventory"),
        "The bytes mapping is the same environment. The name decodes.",
    ),
    # --- the pinned gaps ----------------------------------------------------
    Shape(
        "a number smuggled under an inventoried string name",
        f'import os\nraw = os.environ.get("{_KNOWN}")\nT = int(raw)\n',
        (),
        "GAP, ACCEPTED. The name rule passes because the name is inventoried "
        "and the numeric rule misses the indirection. Closing it needs "
        "data-flow analysis for one case that requires reusing a URL "
        "variable as a number.",
    ),
    Shape(
        "bare truthiness on an inventoried string",
        f'import os\nif os.environ.get("{_KNOWN}"):\n    pass\n',
        (),
        "NOT A GAP. This is the shape the six legitimate presence checks use, "
        "and it is correct for a string whose empty value means unset.",
    ),
    Shape(
        "a read compared against a non-boolean literal",
        f'import os\nF = os.environ.get("{_KNOWN}") == "production"\n',
        (),
        "NOT A GAP. An ordinary string test, which is why the boolean rule "
        "keys on the literal and not on the comparison.",
    ),
    Shape(
        "getattr(os, 'environ')",
        f'import os\nE = getattr(os, "environ")\nF = E.get("{_UNKNOWN}")\n',
        (),
        "GAP, ACCEPTED. Reflection defeats every syntactic rule and there is "
        "no careless way to write it. An author doing this is evading, and a "
        "sweep is not the control for that.",
    ),
)


class TestTheSweepSeesEveryShapeItClaimsTo:
    """The sweep's positive controls, which it had none of until now.

    WHY THIS MATTERS MORE THAN IT LOOKS. Every rule in this file asserts
    ``offenders == []`` against the real tree, and a rule that stopped
    detecting anything at all would pass exactly the same way a clean tree
    does. Nothing distinguished "no offence in the tree" from "the predicate
    is broken" until these rows existed. Each row plants a shape in a source
    string and names the rules that must report it.
    """

    def test_the_table_is_the_size_the_docstrings_claim(self) -> None:
        """The counts the prose above quotes, re-derived rather than recalled.

        A row added without updating those sentences fails here, which is the
        only thing that keeps a docstring full of numbers honest.
        """
        caught_by = [shape.caught_by for shape in SHAPES]
        assert len(SHAPES) == 34
        assert caught_by.count(()) == 4
        assert caught_by.count(("inventory",)) == 19
        assert sum(1 for rules in caught_by if {"numeric", "boolean"} & set(rules)) == 11

    @pytest.mark.parametrize("shape", SHAPES, ids=lambda s: s.label)
    def test_the_rules_that_fire_are_exactly_the_ones_the_table_names(self, shape: Shape) -> None:
        fired = tuple(rule for rule, check in _RULES.items() if check("planted.py", shape.source))
        assert fired == shape.caught_by, (
            f"{shape.label!r} was expected to be caught by {shape.caught_by or '(nothing)'} "
            f"and was caught by {fired or '(nothing)'}. {shape.note}"
        )


class TestEveryEnvironmentReadNamesAnInventoriedVariable:
    """The name at the read site, which is the one thing every spelling shares.

    WHAT THIS RULE IS FOR. The two sweeps above key on what a value is USED
    as. That is why `SHAPES` above holds 19 rows they miss and this one catches
    alone, and the worst of them is not exotic: binding a read to a local
    and calling ``int()`` on the next line defeats the numeric rule
    completely, and it is the way a careless author is most likely to write a
    numeric read. A rule keyed on the CONSUMER can always be evaded by one
    assignment, because the consumer can be arbitrarily far from the read.

    WHAT THE TREE ACTUALLY HOLDS, counted rather than assumed: 55 distinct
    ``POSTERN_*`` variables across the swept roots, in two disjoint
    populations. 18 are read directly, and all 18 are strings -- a URL, a
    path, a key id, an issuer, an audience, a key prefix. 37 are handed to a
    reader as its ``name`` argument, and those are the 32 in `BOUNDED`, the 2
    in `STORE_BOUNDED` and the 3 in `FLAGS`. Nothing is in both and nothing is
    in neither, which
    `TestEveryEnvironmentReadNamesAnInventoriedVariable::test_the_two_inventories_are_the_whole_tree`
    re-derives on every run.

    SO THE DISCRIMINATOR IS THE NAME, held in a list, not the syntax of the
    read. A new flag spelled ``if os.environ.get("POSTERN_NEW_FLAG"):`` fails
    because ``POSTERN_NEW_FLAG`` is in no inventory, and the rule never looks
    at the ``if`` at all. That is what lets it coexist with the six legitimate
    presence checks on ``POSTERN_REDIS_URL``: they read an inventoried string,
    so the rule is silent on all six, and it stays silent no matter how they
    are rewritten.

    TWO OTHER DISCRIMINATORS WERE TRIED AND BOTH FAILED, measured against
    those same six sites on 2026-09-27.

    - THE SHAPE OF THE NAME. There is no convention to key on. The 18 strings
      end in seven different words -- ISSUER four times, URI and URL and PATH
      three each, AUDIENCE and KID twice, PREFIX once -- so a rule keyed on a
      URL-ish suffix covers 9 of the 18 and would read the other 9, including
      ``POSTERN_AUDIENCE`` and both key ids, as not-strings. The flags are
      worse: they share no suffix, and only two of the three share the
      ``REQUIRE_`` prefix, which ``POSTERN_STRICT_HEADERS`` breaks.
    - WHETHER THE VALUE IS DISCARDED AFTER THE TEST. It fires on two of the
      six, `postern_core.auth.revoke_cli`'s ``main`` and
      `config.py`'s `enforce_redis_requirement`, and both firings are wrong:
      each is a presence check on ``POSTERN_REDIS_URL`` that needs the answer
      and not the value. It clears the other four only because they bind the
      value to a local first, which is one line of rewriting away for
      anything trying to hide. A 2-in-6 false-positive rate on a rule that a
      flag evades by assignment is the rule this file's own docstring says
      gets switched off within a week.

    WHAT IT STILL DOES NOT CATCH, and both are in `SHAPES` as rows expected to
    fire nothing: a number read under a name already inventoried as a string,
    and ``getattr(os, "environ")``. The first needs data-flow analysis; the
    second is reflection, which no syntactic rule reaches.

    THE INVENTORY IS A HUMAN GATE, not a mechanical one. An author who adds
    ``POSTERN_NEW_FLAG`` to `READ_AS_STRING` gets their bare truthiness back.
    What the rule buys is that they cannot do it without editing a list whose
    docstring says only strings belong in it, in a diff a reviewer sees.
    """

    def test_every_direct_read_names_a_variable_in_the_string_inventory(self) -> None:
        offenders = [
            f"{site.where} reads {site.name!r}"
            for site in _all_env_sites()
            if site.shape == "direct" and site.name is not None and site.name not in READ_AS_STRING
        ]
        assert offenders == [], (
            f"{offenders} read the environment directly under a name in no inventory. "
            "A number belongs in BOUNDED or STORE_BOUNDED and is read through "
            "postern_core.config's int_from_env or float_from_env; a flag belongs in "
            "FLAGS and is read through bool_from_env; only a string is read directly, "
            "and then its name belongs in READ_AS_STRING in this file."
        )

    def test_every_bounded_reader_call_names_a_variable_in_an_inventory(self) -> None:
        known = BOUNDED_NAMES | STORE_BOUNDED_NAMES | FLAGS
        offenders = [
            f"{site.where} reads {site.name!r}"
            for site in _all_env_sites()
            if site.shape == "reader" and site.name is not None and site.name not in known
        ]
        assert offenders == [], (
            f"{offenders} are read through a bounded reader but are in none of this "
            "file's inventories. This is the gap the two Redis TTLs fell through: "
            "TestEveryNumericSettingIsInTheInventory walks the two from_env methods, "
            "and a reader called anywhere else was invisible to it."
        )

    def test_no_module_reaches_the_environment_without_naming_a_variable(self) -> None:
        offenders = [
            site.where
            for site in _all_env_sites()
            if site.name is None and site.enclosing not in GENERIC_READERS
        ]
        assert offenders == [], (
            f"{offenders} reach the environment without naming a variable this sweep "
            "can resolve -- a built name, a bulk copy, a write, or a seventh generic "
            "reader. Every one of those makes a variable invisible to the two rules "
            f"above. The readers allowed to take a name they were handed are "
            f"{sorted(GENERIC_READERS)}."
        )

    def test_the_two_inventories_are_the_whole_tree(self) -> None:
        """55 variables, 18 read directly and 37 through a reader, disjoint."""
        direct = {s.name for s in _all_env_sites() if s.shape == "direct" and s.name}
        through = {s.name for s in _all_env_sites() if s.shape == "reader" and s.name}
        assert direct & through == set(), (
            f"{sorted(direct & through)} is both read directly and handed to a reader. "
            "One variable read two ways is two bounds that can disagree."
        )
        assert direct == set(READ_AS_STRING)
        assert through == BOUNDED_NAMES | STORE_BOUNDED_NAMES | FLAGS
        assert len(direct) == 18
        assert len(through) == 37

    def test_no_inventoried_string_is_also_a_number_or_a_flag(self) -> None:
        """The partition is asserted on the inventories too, not only the tree."""
        bounded = BOUNDED_NAMES | STORE_BOUNDED_NAMES
        assert READ_AS_STRING & bounded == frozenset()
        assert READ_AS_STRING & FLAGS == frozenset()
        assert bounded & FLAGS == frozenset()

    def test_every_flag_is_read_through_bool_from_env_and_nothing_else(self) -> None:
        """A name in `FLAGS` that some module read directly would be the defect."""
        for site in _all_env_sites():
            assert site.name not in FLAGS or site.shape == "reader", (
                f"{site.where} reads the flag {site.name!r} directly. A flag has four "
                "spellings for yes and four for no, and only bool_from_env knows them."
            )

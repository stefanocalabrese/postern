"""``POSTERN_REQUIRE_REDIS=1`` refuses to start on BOTH services, not one.

THE DEFECT. The variable means "refuse to run with per-replica state". It was
read in `services/api/main.py` and nowhere else, so an operator who set it got
the guarantee on the read path and none at all on the write path -- where, on
26 September 2026, three Redis-backed stores live:

- the ZT-7 revocation list, so a kill switch cut only the replica that
  happened to receive the request;
- the device code store, which since the exchange began marking
  ``exchanged_at`` is single-use -- per replica, a code spent on one replica
  stayed redeemable on every other, which is exactly the multiplier that
  change removed;
- the per-customer approval rate limit counters, so R replicas admitted R
  times each ceiling.

`services/confirm/customer_rate_limit.py`'s factory recorded the gap in prose
and left it open. This file is the gate that closes it.

WHY IT DRIVES THE TWO COMPOSITION ROOTS AND NOT THE HELPER. The helper existed
in effect all along -- five lines inside `create_app` -- and the defect was
never that those five lines were wrong. It was that the second service never
called them. A test of `enforce_redis_requirement` alone would have passed
every day the defect was live, which makes it the wrong test. Every case below
goes through `create_app` or `create_confirm_app`.

WHAT IS PINNED ON THE READ PATH, AND WHY THAT IS HALF THE POINT. Extracting a
guard that one service already had is a chance to change that service by
accident, and this guard had no test of any kind before this file -- a grep for
the variable across ``tests`` returned nothing. So the read path's message,
exception type and exact condition are asserted here against the literals that
were in `create_app` before the extraction, not against whatever the shared
helper now produces.

THE CONDITION IS ``== "1"`` AND NOTHING ELSE, which `TestOnlyTheLiteralOne`
pins as behaviour rather than endorsing. ``POSTERN_REQUIRE_REDIS=true`` buys
no guard on either service. That is the read path's existing contract and
widening it here would change it silently on both, so it is recorded as a
sharp edge and left alone.
"""

from __future__ import annotations

import dataclasses
from typing import Any

import pytest
from fastmcp.server.auth.providers.jwt import JWTVerifier, RSAKeyPair
from postern_core.auth.device_keys import no_enrolled_devices
from postern_core.config import (
    REDIS_URL_ENV,
    REQUIRE_REDIS_ENV,
    REQUIRE_REDIS_ON,
)

from services.api.main import create_app
from services.api.settings import Settings
from services.confirm.main import create_confirm_app
from services.confirm.settings import ConfirmSettings
from tests.test_device_grant import AUDIENCE, ISSUER

#: The read path's refusal, verbatim as it stood in `create_app` before the
#: guard was shared. Reproduced here as one literal so that a change to it
#: fails this file rather than passing quietly.
API_MESSAGE = (
    "POSTERN_REQUIRE_REDIS=1 but POSTERN_REDIS_URL is not set. "
    "This guard only checks that POSTERN_REDIS_URL is configured, "
    "which backs the session store; revocation lists and JTI "
    "replay protection remain in-process per replica regardless "
    "of this setting."
)

#: The sentence both refusals open with, which is the shared half.
SHARED_PREFIX = "POSTERN_REQUIRE_REDIS=1 but POSTERN_REDIS_URL is not set. "

A_URL = "redis://localhost:6379/0"


@pytest.fixture(scope="module")
def key_pair() -> RSAKeyPair:
    """The banking app's assertion signing key, so the confirm app builds.

    Module-scoped because RSA generation is slow and no case here cares which
    key it is -- only that the assertion guard is satisfied, so that the Redis
    guard is what the assertions below are actually observing.
    """
    return RSAKeyPair.generate()


@pytest.fixture(autouse=True)
def _no_redis_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """Neither variable set, whatever the developer's shell exports.

    AUTOUSE AND NOT PER TEST. Both variables are read from the real process
    environment by both composition roots, so a machine that happens to export
    either one would otherwise turn "does not raise" into a test that proves
    nothing. Each case sets what it needs on top of a known-empty baseline.
    """
    monkeypatch.delenv(REQUIRE_REDIS_ENV, raising=False)
    monkeypatch.delenv(REDIS_URL_ENV, raising=False)


def _confirm(key_pair: RSAKeyPair, **overrides: Any) -> Any:
    """The real write-path composition root, with only its two other guards fed.

    The assertion verifier and device key store are the documented keyword
    seams. Passing them means the only thing that can refuse below is the
    Redis guard, which is what makes a raised message attributable.
    """
    return create_confirm_app(
        dataclasses.replace(ConfirmSettings.for_testing(), **overrides),
        assertion_verifier=JWTVerifier(
            public_key=key_pair.public_key, issuer=ISSUER, audience=AUDIENCE
        ),
        device_key_store=no_enrolled_devices(),
    )


# ---------------------------------------------------------------------------
# The write path. This is the defect.
# ---------------------------------------------------------------------------


class TestTheWritePathNowRefuses:
    def test_required_and_absent_refuses_to_build(
        self, key_pair: RSAKeyPair, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """THE FAILING CASE. Before this work `create_confirm_app` returned an
        app here, with three per-replica stores and no complaint."""
        monkeypatch.setenv(REQUIRE_REDIS_ENV, REQUIRE_REDIS_ON)
        with pytest.raises(RuntimeError) as raised:
            _confirm(key_pair)
        assert str(raised.value).startswith(SHARED_PREFIX)

    def test_the_refusal_names_both_variables(
        self, key_pair: RSAKeyPair, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The message is the only thing an operator has at 3am."""
        monkeypatch.setenv(REQUIRE_REDIS_ENV, REQUIRE_REDIS_ON)
        with pytest.raises(RuntimeError) as raised:
            _confirm(key_pair)
        message = str(raised.value)
        assert REQUIRE_REDIS_ENV in message
        assert REDIS_URL_ENV in message

    @pytest.mark.parametrize(
        "store",
        ["revocation", "device code", "rate limit"],
        ids=["revocation-list", "device-code-store", "customer-rate-limit"],
    )
    def test_the_refusal_names_each_affected_store(
        self, store: str, key_pair: RSAKeyPair, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Three stores degrade, so all three are named.

        An operator told only "Redis is required" has to go and find out what
        they lost; one told which three does not.
        """
        monkeypatch.setenv(REQUIRE_REDIS_ENV, REQUIRE_REDIS_ON)
        with pytest.raises(RuntimeError) as raised:
            _confirm(key_pair)
        assert store in str(raised.value)

    def test_the_refusal_says_how_to_get_out_of_it(
        self, key_pair: RSAKeyPair, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Both exits, because this refusal is new and the operator was
        running before it: set the URL, or stop demanding it."""
        monkeypatch.setenv(REQUIRE_REDIS_ENV, REQUIRE_REDIS_ON)
        with pytest.raises(RuntimeError) as raised:
            _confirm(key_pair)
        message = str(raised.value)
        assert f"Set {REDIS_URL_ENV}" in message
        assert f"unset {REQUIRE_REDIS_ENV}" in message

    def test_required_and_present_builds(
        self, key_pair: RSAKeyPair, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The configuration the guard exists to demand must still work.

        No connection is made here -- every factory constructs its client
        lazily -- so this asserts the guard passes, not that Redis answers.
        """
        monkeypatch.setenv(REQUIRE_REDIS_ENV, REQUIRE_REDIS_ON)
        monkeypatch.setenv(REDIS_URL_ENV, A_URL)
        assert _confirm(key_pair) is not None

    def test_not_required_builds_with_no_redis_at_all(self, key_pair: RSAKeyPair) -> None:
        """The development path is untouched.

        ``docker compose``, the test suite and a single-process run all set
        neither variable, and none of them may start failing because a
        production guard landed.
        """
        assert _confirm(key_pair) is not None

    def test_an_empty_url_counts_as_absent(
        self, key_pair: RSAKeyPair, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """``POSTERN_REDIS_URL=`` is how this repository's compose file spells
        "unset", and the factories treat it that way, so the guard must too."""
        monkeypatch.setenv(REQUIRE_REDIS_ENV, REQUIRE_REDIS_ON)
        monkeypatch.setenv(REDIS_URL_ENV, "")
        with pytest.raises(RuntimeError):
            _confirm(key_pair)


class TestTheWritePathStillFailsOnAuthenticationFirst:
    def test_missing_assertion_settings_win_over_the_redis_guard(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Order is a decision, and `create_confirm_app` already made it.

        Its existing comment -- "AFTER the assertion guard, so an operator
        missing both is told about authentication first ... a service that
        authenticates nobody has nothing to verify a signature for" -- sets a
        priority that a new guard must not quietly jump. An operator missing
        authentication AND Redis is told about authentication.
        """
        monkeypatch.setenv(REQUIRE_REDIS_ENV, REQUIRE_REDIS_ON)
        settings = dataclasses.replace(
            ConfirmSettings.for_testing(),
            app_assertion_jwks_uri="",
            app_assertion_issuer="",
            app_assertion_audience="",
        )
        with pytest.raises(ValueError) as raised:
            create_confirm_app(settings, device_key_store=no_enrolled_devices())
        assert "inbound authentication" in str(raised.value)


# ---------------------------------------------------------------------------
# The read path. Unchanged, and pinned so that it stays unchanged.
# ---------------------------------------------------------------------------


class TestTheReadPathIsUnchanged:
    def test_the_message_is_the_literal_it_always_was(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Byte for byte. Sharing the guard must not reword the read path."""
        monkeypatch.setenv(REQUIRE_REDIS_ENV, REQUIRE_REDIS_ON)
        with pytest.raises(RuntimeError) as raised:
            create_app(Settings.for_testing())
        assert str(raised.value) == API_MESSAGE

    def test_required_and_present_builds(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(REQUIRE_REDIS_ENV, REQUIRE_REDIS_ON)
        monkeypatch.setenv(REDIS_URL_ENV, A_URL)
        assert create_app(Settings.for_testing()) is not None

    def test_not_required_builds_with_no_redis_at_all(self) -> None:
        assert create_app(Settings.for_testing()) is not None

    def test_an_empty_url_counts_as_absent(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(REQUIRE_REDIS_ENV, REQUIRE_REDIS_ON)
        monkeypatch.setenv(REDIS_URL_ENV, "")
        with pytest.raises(RuntimeError):
            create_app(Settings.for_testing())


# ---------------------------------------------------------------------------
# One contract, two consequences.
# ---------------------------------------------------------------------------


class TestOneContractTwoConsequences:
    def test_both_services_open_with_the_same_sentence(
        self, key_pair: RSAKeyPair, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The condition and its statement are shared, so the first sentence
        is identical and an operator reading either learns the same fact."""
        monkeypatch.setenv(REQUIRE_REDIS_ENV, REQUIRE_REDIS_ON)
        with pytest.raises(RuntimeError) as api:
            create_app(Settings.for_testing())
        with pytest.raises(RuntimeError) as confirm:
            _confirm(key_pair)
        assert str(api.value).startswith(SHARED_PREFIX)
        assert str(confirm.value).startswith(SHARED_PREFIX)

    def test_the_two_consequences_differ(
        self, key_pair: RSAKeyPair, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """They must differ, because the two services lose different things.

        The read path loses the session store and says so; the write path
        loses a revocation list, a single-use device code and a per-customer
        ceiling. One message covering both would be accurate about neither.
        """
        monkeypatch.setenv(REQUIRE_REDIS_ENV, REQUIRE_REDIS_ON)
        with pytest.raises(RuntimeError) as api:
            create_app(Settings.for_testing())
        with pytest.raises(RuntimeError) as confirm:
            _confirm(key_pair)
        assert str(api.value) != str(confirm.value)
        assert "session store" in str(api.value)
        assert "session store" not in str(confirm.value)

    def test_both_raise_the_same_exception_type(
        self, key_pair: RSAKeyPair, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """``RuntimeError`` on both, which is the read path's existing type.

        It is deliberately NOT the ``ValueError`` that `create_confirm_app`'s
        own two guards raise: those report that this service's configuration
        is incomplete, where this reports that a deployment-wide contract was
        asked for and not supplied. One contract, one type, and the half that
        already existed picked it.
        """
        monkeypatch.setenv(REQUIRE_REDIS_ENV, REQUIRE_REDIS_ON)
        for build in (lambda: create_app(Settings.for_testing()), lambda: _confirm(key_pair)):
            with pytest.raises(RuntimeError):
                build()


class TestOnlyTheLiteralOne:
    """The condition is ``== "1"``. Recorded, not endorsed.

    ``POSTERN_REQUIRE_REDIS=true`` buys no guard on either service, which is a
    sharp edge on a variable whose whole purpose is to be a safety switch.
    Widening it is a change to the read path's existing condition, so it is
    not made here; these cases exist so that the next person to consider it
    finds the current answer written down and fails a test when they change it.
    """

    @pytest.mark.parametrize("value", ["true", "yes", "0", "", " 1", "1 ", "TRUE", "on"])
    def test_no_other_spelling_arms_the_guard_on_either_service(
        self, value: str, key_pair: RSAKeyPair, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(REQUIRE_REDIS_ENV, value)
        assert create_app(Settings.for_testing()) is not None
        assert _confirm(key_pair) is not None

    def test_the_literal_is_exported_rather_than_repeated(self) -> None:
        """Both call sites and this file read one constant, so the condition
        cannot drift between the two services."""
        assert REQUIRE_REDIS_ON == "1"
        assert REQUIRE_REDIS_ENV == "POSTERN_REQUIRE_REDIS"
        assert REDIS_URL_ENV == "POSTERN_REDIS_URL"

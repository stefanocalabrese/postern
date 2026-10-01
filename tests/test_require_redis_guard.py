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
    BOOL_FALSE,
    BOOL_TRUE,
    REDIS_URL_ENV,
    REQUIRE_REDIS_ENV,
    bool_from_env,
)

from services.api.main import create_app
from services.api.settings import Settings
from services.confirm.main import create_confirm_app
from services.confirm.settings import ConfirmSettings
from tests.test_device_grant import AUDIENCE, ISSUER

#: The read path's refusal, verbatim. Reproduced here as one literal so that a
#: change to it fails this file rather than passing quietly.
#:
#: CORRECTED TWICE, AND THE SECOND CORRECTION IS THE INTERESTING ONE. The
#: middle clause first read "revocation lists and JTI replay protection remain
#: in-process per replica regardless of this setting", which was true when it
#: was written and stopped being true two days later, when
#: `create_revocation_store` gained a Redis backend. The replacement fixed the
#: revocation half and kept the jti half, which was accurate about the storage
#: and wrong about what was being stored: it told an operator they were losing
#: replay protection to a missing backend, when `JtiReplayCache` never carried
#: replay protection in any backend. See
#: `dev-docs/decisions/0014-jti-cache-detects-randomness-not-replay.md`.
API_MESSAGE = (
    "POSTERN_REQUIRE_REDIS is set but POSTERN_REDIS_URL is not. "
    "This guard checks only that POSTERN_REDIS_URL is configured. It backs "
    "the session store and the ZT-7 revocation list, which are then shared "
    "across replicas. The jti cache stays per replica and should: it holds "
    "only jtis this process minted itself, so a hit there means uuid4 "
    "repeated itself, not that a token was replayed. Replay is detected by "
    "the token's recipient, which is the gateway and the domain services, "
    "and no backend configured here changes that."
)

#: The sentence both refusals open with, which is the shared half.
#:
#: IT NO LONGER QUOTES A VALUE. It said ``POSTERN_REQUIRE_REDIS=1`` while that
#: was the only spelling that armed the guard; now that four do, naming one of
#: them would misdescribe the three other ways an operator can arrive here.
SHARED_PREFIX = "POSTERN_REQUIRE_REDIS is set but POSTERN_REDIS_URL is not. "

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
        monkeypatch.setenv(REQUIRE_REDIS_ENV, "1")
        with pytest.raises(RuntimeError) as raised:
            _confirm(key_pair)
        assert str(raised.value).startswith(SHARED_PREFIX)

    def test_the_refusal_names_both_variables(
        self, key_pair: RSAKeyPair, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The message is the only thing an operator has at 3am."""
        monkeypatch.setenv(REQUIRE_REDIS_ENV, "1")
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
        monkeypatch.setenv(REQUIRE_REDIS_ENV, "1")
        with pytest.raises(RuntimeError) as raised:
            _confirm(key_pair)
        assert store in str(raised.value)

    def test_the_refusal_says_how_to_get_out_of_it(
        self, key_pair: RSAKeyPair, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Both exits, because this refusal is new and the operator was
        running before it: set the URL, or stop demanding it."""
        monkeypatch.setenv(REQUIRE_REDIS_ENV, "1")
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
        monkeypatch.setenv(REQUIRE_REDIS_ENV, "1")
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
        monkeypatch.setenv(REQUIRE_REDIS_ENV, "1")
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
        monkeypatch.setenv(REQUIRE_REDIS_ENV, "1")
        settings = dataclasses.replace(
            ConfirmSettings.for_testing(),
            app_assertion_jwks_uri="",
            app_assertion_issuer="",
            app_assertion_audience="",
        )
        with pytest.raises(ValueError) as raised:
            create_confirm_app(settings, device_key_store=no_enrolled_devices())
        assert "inbound authentication" in str(raised.value)


class TestTheSessionRefusalComesAfterTheRedisGuard:
    """``_refuse_process_local_sessions`` sits beside this guard and after it.

    The device grant's own refusal of per-process state is narrower -- it is
    about refresh families and recalls, and it has a development flag -- so
    an operator who also set POSTERN_REQUIRE_REDIS hears the deployment-wide
    contract's message first.
    """

    def test_required_and_absent_hears_this_guard_first(
        self, key_pair: RSAKeyPair, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(REQUIRE_REDIS_ENV, "1")
        with pytest.raises(RuntimeError) as raised:
            _confirm(key_pair, allow_process_local_sessions=False)
        assert str(raised.value).startswith(SHARED_PREFIX)

    def test_not_required_and_absent_hears_the_session_refusal(self, key_pair: RSAKeyPair) -> None:
        with pytest.raises(RuntimeError) as raised:
            _confirm(key_pair, allow_process_local_sessions=False)
        assert not str(raised.value).startswith(SHARED_PREFIX)
        assert "POSTERN_ALLOW_PROCESS_LOCAL_SESSIONS" in str(raised.value)


# ---------------------------------------------------------------------------
# The read path. Unchanged, and pinned so that it stays unchanged.
# ---------------------------------------------------------------------------


class TestTheReadPathIsUnchanged:
    def test_the_message_is_the_corrected_literal(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Byte for byte, against the corrected string.

        The point of this test is that the message does not drift by ACCIDENT.
        A deliberate correction updates it here in the same change, which is
        the case it was written to allow.
        """
        monkeypatch.setenv(REQUIRE_REDIS_ENV, "1")
        with pytest.raises(RuntimeError) as raised:
            create_app(Settings.for_testing())
        assert str(raised.value) == API_MESSAGE

    def test_required_and_present_builds(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(REQUIRE_REDIS_ENV, "1")
        monkeypatch.setenv(REDIS_URL_ENV, A_URL)
        assert create_app(Settings.for_testing()) is not None

    def test_not_required_builds_with_no_redis_at_all(self) -> None:
        assert create_app(Settings.for_testing()) is not None

    def test_an_empty_url_counts_as_absent(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(REQUIRE_REDIS_ENV, "1")
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
        monkeypatch.setenv(REQUIRE_REDIS_ENV, "1")
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
        monkeypatch.setenv(REQUIRE_REDIS_ENV, "1")
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
        monkeypatch.setenv(REQUIRE_REDIS_ENV, "1")
        for build in (lambda: create_app(Settings.for_testing()), lambda: _confirm(key_pair)):
            with pytest.raises(RuntimeError):
                build()


class TestEverySpellingAnOperatorMeansAsOn:
    """Four spellings arm the guard, case-folded and whitespace-stripped.

    THE SET IS WHAT CONFIG SYSTEMS EMIT, not what a shell idiom allows.
    ``1`` because it is the documented value every existing deployment uses;
    ``true`` because YAML, Helm, Terraform and JSON all render a boolean that
    way; ``yes`` and ``on`` because YAML 1.1 treats both as booleans, so a
    chart author who quotes them to stop that conversion gets the literal
    word here and plainly means on.

    ``y`` and ``t`` are deliberately NOT in the set, though the old
    ``distutils.util.strtobool`` accepted both. No templating system emits a
    single letter and no operator types one into a deployment manifest; what
    a one-character token does buy is a typo that reads as intent, and this
    is a safety switch. They land in `TestAValueNeitherOnNorOffRefusesToStart`
    below, which is a refusal and not a silent off.
    """

    @pytest.mark.parametrize(
        "value",
        ["1", "true", "TRUE", "True", "yes", "YES", "on", "ON", " 1 ", "true\n", "\tYes "],
    )
    def test_it_arms_the_guard_on_both_services(
        self, value: str, key_pair: RSAKeyPair, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(REQUIRE_REDIS_ENV, value)
        with pytest.raises(RuntimeError):
            create_app(Settings.for_testing())
        with pytest.raises(RuntimeError):
            _confirm(key_pair)


class TestEverySpellingAnOperatorMeansAsOff:
    """Four spellings disarm it, plus unset, plus empty, plus whitespace.

    WHY EMPTY IS "UNSET" AND NOT A THIRD STATE. It is already this
    repository's convention -- `int_from_env` treats ``POSTERN_X=`` as unset
    and says why, and `services/api/settings.py`'s `from_env` collapses ``""``
    to ``None`` for its string fields. It is also what a templating system
    emits for a variable that was absent upstream, which is the common case
    worth optimising for.

    For THIS variable the distinction is unobservable, because its default is
    off and "unset" and "off" therefore give the same answer. It is settled
    here anyway, so that the first caller to pass ``default=True`` inherits a
    decision rather than making a new one: an empty value means the operator
    said nothing, so it takes the default.
    """

    @pytest.mark.parametrize("value", ["0", "false", "FALSE", "no", "off", "OFF", "", "   "])
    def test_it_leaves_the_guard_disarmed_on_both_services(
        self, value: str, key_pair: RSAKeyPair, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(REQUIRE_REDIS_ENV, value)
        assert create_app(Settings.for_testing()) is not None
        assert _confirm(key_pair) is not None

    def test_unset_leaves_it_disarmed(self, key_pair: RSAKeyPair) -> None:
        assert create_app(Settings.for_testing()) is not None
        assert _confirm(key_pair) is not None


class TestAValueNeitherOnNorOffRefusesToStart:
    """THE PART THAT MATTERS MORE THAN THE ACCEPTING SET.

    ``POSTERN_REQUIRE_REDIS=maybe`` could be read three ways: off, on, or
    refuse. Off is the defect this whole change exists to remove -- it is
    exactly what ``=true`` did yesterday, a safety switch silently disarmed by
    a spelling. On is worse than it looks: the same reader serves every
    boolean, and ``=disabled`` would then ENABLE the thing the operator was
    turning off, which is the failure in the opposite direction and harder to
    notice.

    So it refuses, and the precedent is one function up in the same module.
    `int_from_env`'s docstring: "a value an operator typed and got wrong must
    fail when the app is assembled, because silently keeping the default means
    the variable they set to fix an outage did nothing, and they find out from
    the same alert they were already looking at." A bool is not different in
    kind; it is the same mistake with fewer characters.
    """

    @pytest.mark.parametrize("value", ["maybe", "2", "-1", "enabled", "y", "t", "1 and 2", "no!"])
    def test_both_services_refuse_to_build(
        self, value: str, key_pair: RSAKeyPair, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(REQUIRE_REDIS_ENV, value)
        with pytest.raises(ValueError):
            create_app(Settings.for_testing())
        with pytest.raises(ValueError):
            _confirm(key_pair)

    def test_the_refusal_names_the_variable_the_value_and_what_is_accepted(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """An operator who mistyped needs all three to fix it in one restart."""
        monkeypatch.setenv(REQUIRE_REDIS_ENV, "maybe")
        with pytest.raises(ValueError) as raised:
            create_app(Settings.for_testing())
        message = str(raised.value)
        assert REQUIRE_REDIS_ENV in message
        assert "'maybe'" in message
        for accepted in sorted(BOOL_TRUE) + sorted(BOOL_FALSE):
            assert accepted in message

    def test_it_is_a_value_error_and_not_the_guards_runtime_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Two different failures deserve two types.

        ``ValueError`` means a value could not be parsed, which is what every
        numeric reader in this module already raises. ``RuntimeError`` is
        reserved for the guard's own finding: the value parsed, it said yes,
        and the URL it demands is missing.
        """
        monkeypatch.setenv(REQUIRE_REDIS_ENV, "maybe")
        with pytest.raises(ValueError) as raised:
            create_app(Settings.for_testing())
        assert not isinstance(raised.value, RuntimeError)


class TestTheTwoServicesCannotDisagree:
    """One contract, one answer, asserted over every spelling in this file.

    The two composition roots read the same function, so this cannot drift
    without someone editing it to. That is precisely why it is worth pinning:
    the defect this pair of changes fixes began as one service reading a
    variable the other ignored.
    """

    @pytest.mark.parametrize(
        "value",
        ["1", "true", "YES", "on", " 1 ", "0", "false", "off", "", "   ", "maybe", "2", "y"],
    )
    def test_both_services_reach_the_same_verdict(
        self, value: str, key_pair: RSAKeyPair, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(REQUIRE_REDIS_ENV, value)

        def verdict(build: Any) -> str:
            try:
                build()
            except ValueError as exc:
                # `RuntimeError` is not a `ValueError`, so the guard's own
                # refusal cannot be caught here and mislabelled.
                return f"unparseable:{type(exc).__name__}"
            except RuntimeError:
                return "armed"
            return "disarmed"

        assert verdict(lambda: create_app(Settings.for_testing())) == verdict(
            lambda: _confirm(key_pair)
        )


class TestTheReaderIsGeneralAndNotAOneOff:
    """`bool_from_env` is the shape, not a `POSTERN_REQUIRE_REDIS` special case.

    TWO OTHER BOOLEAN VARIABLES EXIST AND ARE DELIBERATELY NOT CONVERTED:
    ``POSTERN_STRICT_HEADERS`` and ``POSTERN_REQUIRE_PEM_KEY``, both still
    ``== "1"``. Converting either would change its behaviour rather than
    preserve it -- ``POSTERN_STRICT_HEADERS=true`` means off today and would
    mean on, and ``=maybe`` means off today and would refuse to start -- so
    each is a decision its own owner makes, not a side effect of this one.
    The inconsistency is real and is recorded here rather than hidden.
    """

    def test_it_reads_an_arbitrary_variable(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("POSTERN_SOME_OTHER_FLAG", "yes")
        assert bool_from_env("POSTERN_SOME_OTHER_FLAG", False, because="a test flag") is True

    def test_an_unset_variable_takes_the_default_either_way(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("POSTERN_SOME_OTHER_FLAG", raising=False)
        assert bool_from_env("POSTERN_SOME_OTHER_FLAG", False, because="a test flag") is False
        assert bool_from_env("POSTERN_SOME_OTHER_FLAG", True, because="a test flag") is True

    def test_an_empty_value_takes_the_default_including_a_true_one(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The case that makes "empty means unset" observable.

        With ``default=True`` the two readings finally differ, and this pins
        the one chosen: an empty value is the operator saying nothing.
        """
        monkeypatch.setenv("POSTERN_SOME_OTHER_FLAG", "")
        assert bool_from_env("POSTERN_SOME_OTHER_FLAG", True, because="a test flag") is True

    def test_the_because_sentence_reaches_the_operator(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Same contract as `int_from_env`: the caller says what the flag is
        for, and the refusal carries it, so the reason is in the failure and
        not only in a comment somebody would have to go and find."""
        monkeypatch.setenv("POSTERN_SOME_OTHER_FLAG", "perhaps")
        with pytest.raises(ValueError) as raised:
            bool_from_env("POSTERN_SOME_OTHER_FLAG", False, because="It gates the widget.")
        assert "It gates the widget." in str(raised.value)

    def test_the_two_sets_are_disjoint_and_lower_case(self) -> None:
        """A token in both sets would make the reader's answer depend on the
        order its branches happen to be written in."""
        assert BOOL_TRUE & BOOL_FALSE == frozenset()
        assert all(token == token.lower().strip() for token in BOOL_TRUE | BOOL_FALSE)

    def test_the_sets_are_what_this_file_claims(self) -> None:
        """Narrowing or widening either set is a deliberate act, and it fails
        here first."""
        assert BOOL_TRUE == frozenset({"1", "true", "yes", "on"})
        assert BOOL_FALSE == frozenset({"0", "false", "no", "off"})

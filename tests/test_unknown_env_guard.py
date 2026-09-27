"""A ``POSTERN_*`` variable nothing reads is a typo, and both services say so.

THE DEFECT CLASS, and it is the one every other guard in this family is blind
to by construction. `postern_core/config.py`'s readers each take a NAME and
check the VALUE behind it: `int_from_env` refuses ``POSTERN_CACHE_TTL_SECONDS=0``
and `bool_from_env` refuses ``POSTERN_REQUIRE_REDIS=maybe``. Neither can see
``POSTERN_REQUIRE_REDDIS=1``, because nothing asks for that name, so the value
behind it is never read and an unset variable is indistinguishable from one
that was never meant to be set. The operator armed nothing and learned nothing.
`tests/test_settings_bounds.py`'s AST sweep is blind for the same reason one
level up: it polices the names the CODE reads, and a misspelling exists only in
the ENVIRONMENT.

WHY IT IS WORTH A CONTROL RATHER THAN A DOCUMENTATION LINE. The three flags are
safety switches -- ``POSTERN_REQUIRE_REDIS`` refuses per-replica state,
``POSTERN_REQUIRE_PEM_KEY`` refuses an ephemeral signing key,
``POSTERN_STRICT_HEADERS`` arms MCP header validation -- and a switch that
silently fails to arm is the exact shape this repository has now been bitten by
twice: ``POSTERN_REQUIRE_PEM_KEY=true`` meant "do not require a PEM key" until
2026-09-26, and ``POSTERN_REQUIRE_REDIS`` was enforced on one of two services
until the same day. Both were spelling problems. Only the name half was left.

WHAT THIS FILE PINS: the three populations `classify_environment` sorts a
deployment's variables into, which of them refuses, the escape hatch that keeps
the refusal survivable, and that both composition roots actually call it.
`tests/test_settings_bounds.py` pins the other half -- that the inventory the
guard reads still matches the names the tree reads -- and neither file can be
green while the two disagree.
"""

from __future__ import annotations

import dataclasses
import logging

import pytest
from fastmcp.server.auth.providers.jwt import JWTVerifier, RSAKeyPair
from postern_core.auth.device_keys import no_enrolled_devices
from postern_core.env_inventory import (
    ALLOWED_UNREAD_ENV,
    INVENTORY,
    KNOWN_ENV,
    classify_environment,
    enforce_known_environment,
    names_read_by,
)

from services.api.main import create_app
from services.api.settings import Settings
from services.confirm.main import create_confirm_app
from services.confirm.settings import ConfirmSettings
from tests.test_device_grant import AUDIENCE, ISSUER

API = names_read_by("api")
CONFIRM = names_read_by("confirm")


@pytest.fixture(autouse=True)
def _no_postern_variables(monkeypatch: pytest.MonkeyPatch) -> None:
    """Start every case from an environment this repository configures nothing in.

    A developer's shell, or a previous test, may hold a ``POSTERN_*`` variable,
    and every assertion here is about the exact set the guard sees.
    """
    import os

    for name in [key for key in os.environ if key.upper().startswith("POSTERN_")]:
        monkeypatch.delenv(name, raising=False)


class TestTheThreePopulations:
    """A name this service reads, a name the other one reads, a name neither does."""

    def test_a_name_this_service_reads_is_silent(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("POSTERN_CACHE_TTL_SECONDS", "60")
        report = classify_environment("api")
        assert report.unknown == ()
        assert report.unread == ()

    def test_every_name_in_the_inventory_is_silent_for_the_service_that_reads_it(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The whole inventory at once, which is the case a deployment is."""
        for service, names in (("api", API), ("confirm", CONFIRM)):
            for name in names:
                monkeypatch.setenv(name, "x")
            report = classify_environment(service)
            assert report.unknown == (), f"{service} refused its own variables"
            assert report.unread == (), f"{service} called its own variables unread"
            for name in names:
                monkeypatch.delenv(name)

    def test_the_other_services_variable_is_reported_unread_and_never_refused(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """POPULATION 2. One env file for two deployables is a deployment, not a typo.

        ``docker-compose.yml`` gives each service its own ``environment:``
        block so it cannot happen there, but a single ECS task definition or
        one Helm values file feeding both charts easily does. Refusing this
        would make the guard unusable in exactly the deployments that most
        need it, so it is reported and never raised on.
        """
        monkeypatch.setenv("POSTERN_CONFIRM_MAX_BODY_BYTES", "65536")
        report = classify_environment("api")
        assert report.unknown == ()
        assert report.unread == ("POSTERN_CONFIRM_MAX_BODY_BYTES",)

    def test_an_api_only_flag_set_on_the_write_path_is_reported(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The case that gives population 2 teeth rather than tidiness.

        ``POSTERN_REQUIRE_PEM_KEY`` is read in `services/api/main.py` and
        nowhere else. An operator who sets it on the write path believes they
        refused an ephemeral WRITE key, and `services/confirm` has no such
        guard -- the same one-service-of-two shape that
        ``POSTERN_REQUIRE_REDIS`` was in until 2026-09-26. Nothing here fixes
        that; it makes it visible at startup instead of never.
        """
        monkeypatch.setenv("POSTERN_REQUIRE_PEM_KEY", "1")
        assert classify_environment("confirm").unread == ("POSTERN_REQUIRE_PEM_KEY",)
        assert classify_environment("api").unread == ()

    def test_a_name_neither_service_reads_is_unknown(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """POPULATION 3, the one worth refusing on."""
        monkeypatch.setenv("POSTERN_REQUIRE_REDDIS", "1")
        report = classify_environment("api")
        assert [unknown.name for unknown in report.unknown] == ["POSTERN_REQUIRE_REDDIS"]
        assert report.unread == ()


class TestTheNearestNameThatIsRead:
    """The suggestion is the whole value of the message at 3am."""

    @pytest.mark.parametrize(
        ("typo", "meant"),
        [
            ("POSTERN_REQUIRE_REDDIS", "POSTERN_REQUIRE_REDIS"),
            ("POSTERN_STRICT_HEADER", "POSTERN_STRICT_HEADERS"),
            ("POSTERN_DATABASE_POOLSIZE", "POSTERN_DATABASE_POOL_SIZE"),
            ("POSTERN_REDIS_UR", "POSTERN_REDIS_URL"),
            ("POSTERN_REQUIRE_PEM_KEYS", "POSTERN_REQUIRE_PEM_KEY"),
            ("POSTERN_MAX_BODY_BYTE", "POSTERN_MAX_BODY_BYTES"),
        ],
    )
    def test_the_obvious_typo_gets_the_name_it_meant(
        self, monkeypatch: pytest.MonkeyPatch, typo: str, meant: str
    ) -> None:
        monkeypatch.setenv(typo, "1")
        (unknown,) = classify_environment("api").unknown
        assert unknown.name == typo
        assert unknown.suggestion == meant

    def test_a_name_resembling_nothing_gets_no_suggestion(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Refused all the same. A wrong guess is worse than none."""
        monkeypatch.setenv("POSTERN_SIDECAR_SCRAPE_TOKEN", "x")
        (unknown,) = classify_environment("api").unknown
        assert unknown.suggestion is None

    def test_a_name_the_other_service_reads_is_never_suggested_as_a_typo(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """It is in `KNOWN_ENV`, so it is population 2 and never reaches a suggestion."""
        monkeypatch.setenv("POSTERN_CONFIRM_RATE_LIMIT_TOKEN", "5")
        report = classify_environment("api")
        assert report.unknown == ()

    def test_a_typo_of_the_other_services_variable_suggests_that_variable(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The suggestion pool is every name the CODEBASE reads, not this service's.

        An operator misspelling a confirm variable while deploying the api
        service has made the same mistake and deserves the same answer.
        """
        monkeypatch.setenv("POSTERN_CONFIRM_RATE_LIMIT_TOKENS", "5")
        (unknown,) = classify_environment("api").unknown
        assert unknown.suggestion == "POSTERN_CONFIRM_RATE_LIMIT_TOKEN"


class TestCaseAndSurroundingWhitespace:
    """``postern_require_redis`` is not ``POSTERN_REQUIRE_REDIS`` on Linux."""

    def test_a_lower_case_name_is_caught_and_named(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The container runs Linux, where the two are different variables.

        `bool_from_env` lower-cases the VALUE it reads and this deliberately
        does not lower-case the NAME: a value is a token an operator typed for
        this program to interpret, and a name is a key the operating system
        matches byte for byte.
        """
        monkeypatch.setenv("postern_require_redis", "1")
        (unknown,) = classify_environment("api").unknown
        assert unknown.name == "postern_require_redis"
        assert unknown.suggestion == "POSTERN_REQUIRE_REDIS"

    def test_a_padded_name_is_caught_and_named(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """What a hand-edited env file produces, and the shell will accept."""
        monkeypatch.setenv("POSTERN_REQUIRE_REDIS ", "1")
        (unknown,) = classify_environment("api").unknown
        assert unknown.suggestion == "POSTERN_REQUIRE_REDIS"

    def test_a_correctly_spelled_name_beside_a_lower_case_one_still_refuses(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Having got it right once does not excuse the copy that is wrong."""
        monkeypatch.setenv("POSTERN_REQUIRE_REDIS", "1")
        monkeypatch.setenv("postern_require_redis", "1")
        (unknown,) = classify_environment("api").unknown
        assert unknown.name == "postern_require_redis"


class TestTheScopeIsThePosternNamespace:
    """Everything outside ``POSTERN_*`` is somebody else's."""

    @pytest.mark.parametrize("name", ["PATH", "HOME", "AWS_REGION", "PGPASSWORD", "POSTERNX"])
    def test_a_variable_outside_the_namespace_is_invisible(
        self, monkeypatch: pytest.MonkeyPatch, name: str
    ) -> None:
        monkeypatch.setenv(name, "x")
        report = classify_environment("api")
        assert report.unknown == ()
        assert report.unread == ()

    def test_the_prefix_must_be_followed_by_an_underscore(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """``POSTERNX`` is not in this namespace and ``POSTERN_X`` is.

        A prefix test of ``POSTERN`` alone would claim a namespace this
        application does not own and refuse on a variable belonging to anything
        whose name merely starts with the same seven letters.
        """
        monkeypatch.setenv("POSTERNX_THING", "x")
        assert classify_environment("api").unknown == ()
        monkeypatch.setenv("POSTERN_THING", "x")
        assert len(classify_environment("api").unknown) == 1


class TestTheEscapeHatch:
    """What keeps a refusal over a no-op from being a crash loop."""

    def test_a_declared_name_is_accepted(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("POSTERN_SIDECAR_SCRAPE_TOKEN", "x")
        monkeypatch.setenv(ALLOWED_UNREAD_ENV, "POSTERN_SIDECAR_SCRAPE_TOKEN")
        report = classify_environment("api")
        assert report.unknown == ()
        assert report.declared == ("POSTERN_SIDECAR_SCRAPE_TOKEN",)

    def test_several_names_separated_by_commas(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("POSTERN_ONE", "x")
        monkeypatch.setenv("POSTERN_TWO", "x")
        monkeypatch.setenv(ALLOWED_UNREAD_ENV, " POSTERN_ONE , POSTERN_TWO ,, ")
        assert classify_environment("api").unknown == ()

    def test_it_declares_one_name_and_not_a_family(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """No wildcards. A prefix would re-open the namespace it is narrowing.

        ``POSTERN_SIDECAR_*`` would let a typo inside that family through
        silently, which is the defect this guard exists for. One name, one
        line, one review.
        """
        monkeypatch.setenv("POSTERN_SIDECAR_SCRAPE_TOKEN", "x")
        monkeypatch.setenv(ALLOWED_UNREAD_ENV, "POSTERN_SIDECAR_*")
        assert len(classify_environment("api").unknown) == 1

    def test_declaring_a_name_that_is_not_set_is_not_an_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """One env file serves several deployments; a name may be absent here."""
        monkeypatch.setenv(ALLOWED_UNREAD_ENV, "POSTERN_NOT_SET_ANYWHERE")
        report = classify_environment("api")
        assert report.unknown == ()
        assert report.declared == ()

    def test_the_hatch_is_itself_in_the_inventory(self) -> None:
        """Or the guard would refuse on the variable that configures it."""
        assert ALLOWED_UNREAD_ENV in KNOWN_ENV
        assert ALLOWED_UNREAD_ENV in names_read_by("api")
        assert ALLOWED_UNREAD_ENV in names_read_by("confirm")

    def test_a_misspelt_hatch_fails_loudly_rather_than_silently_off(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """THE HOLE THE HATCH IS NOT.

        A variable that turns a check off is a ``POSTERN_*`` name someone can
        misspell, and a misspelt off switch that turned the check off would be
        worse than no check. It cannot: the misspelling is itself an unread
        ``POSTERN_*`` name, so the guard refuses -- and the refusal names the
        hatch as the nearest name that is read, which is the fix. The
        operator's stray variable is refused too, in the same message.
        """
        monkeypatch.setenv("POSTERN_SIDECAR_SCRAPE_TOKEN", "x")
        monkeypatch.setenv("POSTERN_ALLOWED_UNREAD_EVN", "POSTERN_SIDECAR_SCRAPE_TOKEN")
        report = classify_environment("api")
        refused = {unknown.name: unknown.suggestion for unknown in report.unknown}
        assert refused == {
            "POSTERN_SIDECAR_SCRAPE_TOKEN": None,
            "POSTERN_ALLOWED_UNREAD_EVN": ALLOWED_UNREAD_ENV,
        }

    def test_the_hatch_cannot_silence_a_name_the_other_service_reads(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """It admits unknown names. Population 2 is already never refused."""
        monkeypatch.setenv("POSTERN_CONFIRM_MAX_BODY_BYTES", "1")
        monkeypatch.setenv(ALLOWED_UNREAD_ENV, "POSTERN_CONFIRM_MAX_BODY_BYTES")
        assert classify_environment("api").unread == ("POSTERN_CONFIRM_MAX_BODY_BYTES",)


class TestWhatTheRefusalSays:
    """An operator reading it learns the variable, that it is unread, and the fix."""

    def test_it_refuses_naming_the_variable_and_the_name_it_meant(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("POSTERN_REQUIRE_REDDIS", "1")
        with pytest.raises(RuntimeError) as raised:
            enforce_known_environment(service="api")
        message = str(raised.value)
        assert "POSTERN_REQUIRE_REDDIS" in message
        assert "POSTERN_REQUIRE_REDIS" in message
        assert ALLOWED_UNREAD_ENV in message

    def test_the_value_is_never_echoed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """An unread variable may be a secret meant for something else.

        The numeric readers echo the offending value on the stated ground that
        it is the operator's own environment. That argument does not reach
        here: this guard fires on names it does not recognise, so it cannot
        know what the value behind one is, and a stray ``POSTERN_`` name is
        exactly where an operator's unrelated token ends up.
        """
        monkeypatch.setenv("POSTERN_REQUIRE_REDDIS", "hunter2-not-a-real-secret")
        with pytest.raises(RuntimeError) as raised:
            enforce_known_environment(service="api")
        assert "hunter2" not in str(raised.value)

    def test_every_unknown_name_is_named_not_only_the_first(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """An operator fixing one at a time redeploys once per typo."""
        monkeypatch.setenv("POSTERN_REQUIRE_REDDIS", "1")
        monkeypatch.setenv("POSTERN_STRICT_HEADER", "1")
        with pytest.raises(RuntimeError) as raised:
            enforce_known_environment(service="api")
        message = str(raised.value)
        assert "POSTERN_REQUIRE_REDDIS" in message
        assert "POSTERN_STRICT_HEADER" in message

    def test_the_names_are_reported_in_a_stable_order(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """``os.environ`` iterates in insertion order, which a deployment sets."""
        monkeypatch.setenv("POSTERN_ZZZ", "1")
        monkeypatch.setenv("POSTERN_AAA", "1")
        assert [u.name for u in classify_environment("api").unknown] == [
            "POSTERN_AAA",
            "POSTERN_ZZZ",
        ]

    def test_a_clean_environment_raises_nothing(self) -> None:
        enforce_known_environment(service="api")
        enforce_known_environment(service="confirm")

    def test_an_unread_name_warns_and_does_not_raise(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        monkeypatch.setenv("POSTERN_CONFIRM_MAX_BODY_BYTES", "1")
        with caplog.at_level(logging.WARNING, logger="postern_core.env_inventory"):
            enforce_known_environment(service="api")
        assert "POSTERN_CONFIRM_MAX_BODY_BYTES" in caplog.text

    def test_one_line_is_logged_however_many_names_are_unread(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        """A per-variable line on a shared env file is a log nobody reads."""
        for name in sorted(CONFIRM - names_read_by("api")):
            monkeypatch.setenv(name, "1")
        with caplog.at_level(logging.WARNING, logger="postern_core.env_inventory"):
            enforce_known_environment(service="api")
        assert len(caplog.records) == 1


class TestTheInventoryIsInternallyConsistent:
    """Properties of the table that no AST sweep would notice."""

    def test_every_name_is_in_the_namespace_the_guard_scans(self) -> None:
        assert all(entry.name.startswith("POSTERN_") for entry in INVENTORY)

    def test_no_name_appears_twice(self) -> None:
        names = [entry.name for entry in INVENTORY]
        assert len(names) == len(set(names))

    def test_every_name_is_read_by_at_least_one_service(self) -> None:
        assert all(entry.services for entry in INVENTORY)

    def test_the_two_services_together_are_the_whole_inventory(self) -> None:
        assert names_read_by("api") | names_read_by("confirm") == KNOWN_ENV

    def test_an_unknown_service_is_a_programming_error(self) -> None:
        with pytest.raises(ValueError, match="stub"):
            names_read_by("stub")

    def test_every_kind_is_one_of_three(self) -> None:
        assert {entry.kind for entry in INVENTORY} == {"string", "number", "flag"}


# ---------------------------------------------------------------------------
# Both composition roots, which is where the constraint puts this check.
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def key_pair() -> RSAKeyPair:
    """The banking app's assertion signing key, so the write-path app builds.

    Module-scoped because RSA generation is slow and no case here cares which
    key it is -- only that the assertion guard is satisfied, so that a refusal
    is attributable to the guard under test. Mirrors
    `tests/test_require_redis_guard.py`, which needed the same thing for the
    same reason.
    """
    return RSAKeyPair.generate()


def _confirm(key_pair: RSAKeyPair) -> object:
    """The real write-path root with its other two guards fed."""
    return create_confirm_app(
        ConfirmSettings.for_testing(),
        assertion_verifier=JWTVerifier(
            public_key=key_pair.public_key, issuer=ISSUER, audience=AUDIENCE
        ),
        device_key_store=no_enrolled_devices(),
    )


class TestBothCompositionRootsCallIt:
    """A guard only one root calls is the defect POSTERN_REQUIRE_REDIS was.

    That variable was read in `services/api/main.py` and nowhere else until
    2026-09-26, so an operator who set it got the guarantee on the read path and
    none on the write path -- which holds the write key and three Redis-backed
    stores. The same mistake is available here and this class is what refuses it:
    both roots, each driven for real rather than grepped for a call.
    """

    def test_the_read_path_refuses_to_build(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("POSTERN_REQUIRE_REDDIS", "1")
        with pytest.raises(RuntimeError, match="POSTERN_REQUIRE_REDDIS"):
            create_app(Settings.for_testing())

    def test_the_write_path_refuses_to_build(
        self, key_pair: RSAKeyPair, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("POSTERN_REQUIRE_REDDIS", "1")
        with pytest.raises(RuntimeError, match="POSTERN_REQUIRE_REDDIS"):
            _confirm(key_pair)

    def test_both_build_on_a_clean_environment(
        self, key_pair: RSAKeyPair, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The other half of the pair, and the one that would catch over-reach.

        A guard that refused something legitimate would make every deployment
        fail, so this asserts the ordinary case: nothing stray set, both roots
        build. ``Settings.for_testing()`` and ``ConfirmSettings.for_testing()``
        read no environment variables of their own.
        """
        assert create_app(Settings.for_testing()) is not None
        assert _confirm(key_pair) is not None

    def test_it_refuses_before_the_read_paths_other_guards(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A typo is the explanation for what the later guards would report.

        ``POSTERN_REQUIRE_REDIS=1`` with no URL is a `RuntimeError` from
        `enforce_redis_requirement`. Add a misspelt variable and this guard
        answers instead, because an operator who typed one name wrongly has
        probably typed the one the other guard is complaining about.
        """
        monkeypatch.setenv("POSTERN_REQUIRE_REDIS", "1")
        monkeypatch.delenv("POSTERN_REDIS_URL", raising=False)
        monkeypatch.setenv("POSTERN_REQUIRE_REDDIS", "1")
        with pytest.raises(RuntimeError) as raised:
            create_app(Settings.for_testing())
        assert "POSTERN_REQUIRE_REDDIS" in str(raised.value)

    def test_it_refuses_before_the_write_paths_authentication_guard(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """THE ONE ORDERING DECISION THIS WORK CHANGES, stated rather than slipped in.

        `tests/test_require_redis_guard.py`'s
        `TestTheWritePathStillFailsOnAuthenticationFirst` pins that an operator
        missing authentication AND Redis hears about authentication, because
        authentication is the outer control. This guard goes ahead of BOTH, and
        that is not the same kind of jump: those two read VALUES and report a
        configuration that is incomplete, while this reads NAMES and, when it
        fires, names the reason the configuration looks incomplete. A typo in
        ``POSTERN_APP_ASSERTION_JWKS_URI`` makes the assertion guard send an
        operator to check a line they already wrote correctly.

        The pinned ordering is untouched when nothing is misspelt, which is the
        case that test drives.
        """
        monkeypatch.setenv("POSTERN_APP_ASSERTION_JWKS_UR", "https://app.test/jwks")
        settings = dataclasses.replace(
            ConfirmSettings.for_testing(),
            app_assertion_jwks_uri="",
            app_assertion_issuer="",
            app_assertion_audience="",
        )
        with pytest.raises(RuntimeError) as raised:
            create_confirm_app(settings, device_key_store=no_enrolled_devices())
        message = str(raised.value)
        assert "POSTERN_APP_ASSERTION_JWKS_UR" in message
        assert "POSTERN_APP_ASSERTION_JWKS_URI" in message

    def test_the_hatch_lets_both_roots_build(
        self, key_pair: RSAKeyPair, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """What an operator with a genuine stray variable does, end to end."""
        monkeypatch.setenv("POSTERN_SIDECAR_SCRAPE_TOKEN", "x")
        monkeypatch.setenv(ALLOWED_UNREAD_ENV, "POSTERN_SIDECAR_SCRAPE_TOKEN")
        assert create_app(Settings.for_testing()) is not None
        assert _confirm(key_pair) is not None

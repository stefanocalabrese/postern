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
import os
import subprocess
import sys
from pathlib import Path

import pytest
from fastmcp.server.auth.providers.jwt import JWTVerifier, RSAKeyPair
from postern_core.auth.device_keys import no_enrolled_devices
from postern_core.env_inventory import (
    ALLOWED_UNREAD_ENV,
    INVENTORY,
    KNOWN_ENV,
    REQUIRED_ENV,
    SERVICES,
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

    def test_the_removed_attempt_budget_refuses_the_write_path(
        self, key_pair: RSAKeyPair, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """``POSTERN_USER_CODE_MAX_ATTEMPTS`` left with the attempt budget it
        set (spec section 9). An operator still setting it believes a limit is
        armed that no longer exists, so it is a name nothing reads."""
        monkeypatch.setenv("POSTERN_USER_CODE_MAX_ATTEMPTS", "5")
        with pytest.raises(RuntimeError, match="POSTERN_USER_CODE_MAX_ATTEMPTS"):
            _confirm(key_pair)

    def test_the_removed_attempt_budget_refuses_the_read_path(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("POSTERN_USER_CODE_MAX_ATTEMPTS", "5")
        with pytest.raises(RuntimeError, match="POSTERN_USER_CODE_MAX_ATTEMPTS"):
            create_app(Settings.for_testing())

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


# ---------------------------------------------------------------------------
# The mirror: a variable that is absent and needed.
# ---------------------------------------------------------------------------


class TestWhatTheRequirementListIsForAndWhatItIsNot:
    """The scope of this half, which is narrower than it first looks.

    THE CASE IT DOES NOT COVER, and it is the one the idea is usually sold on:
    the whole environment going missing. If a ConfigMap is dropped entirely then
    ``POSTERN_REQUIRED_ENV`` is dropped with it, no requirement is declared, and
    a list-in-the-environment is vacuous by construction.

    THAT CASE IS ALREADY FATAL, which is why the gap is worth closing anyway
    rather than being the whole point. Measured with every ``POSTERN_`` variable
    deleted: `services/api`'s `Settings.from_env` raises ``KeyError:
    'POSTERN_BACKEND_BASE_URL'`` because that one read is a subscript, and
    `create_confirm_app` raises `ValueError` naming the three
    ``POSTERN_APP_ASSERTION_*`` settings. Neither service can start on an empty
    environment, so a total loss is loud without any help from here.

    WHAT IS LEFT, AND IS SILENT TODAY: ONE key dropped or renamed, on a variable
    that has a default. That is the whole remaining population and every member
    of it is a control being disarmed -- ``POSTERN_REQUIRE_REDIS`` absent means
    per-replica state accepted, ``POSTERN_REQUIRE_PEM_KEY`` absent means an
    ephemeral signing key accepted, ``POSTERN_REDIS_URL`` absent means four
    stores go in-memory, ``POSTERN_JWKS_URI`` absent means the read path serves
    with no customer authentication at all. Each of those is a deployment that
    starts, serves, and is weaker than the operator believes.
    """

    def test_a_required_variable_that_is_set_satisfies_the_requirement(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(REQUIRED_ENV, "POSTERN_REQUIRE_REDIS")
        monkeypatch.setenv("POSTERN_REQUIRE_REDIS", "1")
        report = classify_environment("api")
        assert report.absent == ()
        assert report.blank == ()

    def test_a_required_variable_that_is_absent_is_reported(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(REQUIRED_ENV, "POSTERN_REQUIRE_REDIS")
        assert classify_environment("api").absent == ("POSTERN_REQUIRE_REDIS",)

    def test_several_requirements_separated_by_commas(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Same format as the hatch, for the reason one format is better than two."""
        monkeypatch.setenv(REQUIRED_ENV, " POSTERN_REQUIRE_REDIS , POSTERN_REDIS_URL ,, ")
        monkeypatch.setenv("POSTERN_REDIS_URL", "redis://x")
        assert classify_environment("api").absent == ("POSTERN_REQUIRE_REDIS",)

    def test_an_empty_requirement_list_requires_nothing(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(REQUIRED_ENV, "")
        report = classify_environment("api")
        assert report.absent == ()
        assert report.unsatisfiable == ()

    def test_the_names_are_reported_in_a_stable_order(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Sorted, not in the order the operator happened to type them."""
        monkeypatch.setenv(REQUIRED_ENV, "POSTERN_REDIS_URL,POSTERN_JWKS_URI")
        assert classify_environment("api").absent == ("POSTERN_JWKS_URI", "POSTERN_REDIS_URL")


class TestPresentMeansCarryingAValue:
    """Set but empty does NOT satisfy a requirement, and this is the ruling.

    WHY, AND IT IS NOT MERELY CONSISTENCY. An empty value is what the failure
    being guarded against PRODUCES. A Helm template rendering
    ``{{ .Values.redisUrl }}`` with nothing behind it emits an empty string; an
    ECS task definition carrying ``{"name": "POSTERN_REDIS_URL", "value": ""}``
    emits an empty string; an ``env_file`` line left as ``POSTERN_REDIS_URL=``
    emits an empty string. If empty satisfied the requirement, the control would
    pass in the single most likely shape of the defect it exists for.

    IT IS ALSO THE CONVENTION EVERYWHERE ELSE. `int_from_env`, `float_from_env`
    and `bool_from_env` all return their default for ``""``;
    `services/api/settings.py`'s `from_env` collapses ``""`` to ``None`` for its
    string fields; `enforce_redis_requirement` treats an empty
    ``POSTERN_REDIS_URL`` as absent. A requirement check that called ``""``
    present would be the one place in this repository where an empty value means
    something.

    AND NO LEGITIMATE VALUE IS REFUSED. Every variable a deployment can be
    asked to provide is a URL, a path, a key id, an issuer, an audience, a
    number or a flag. None of them has a meaningful empty value, and for the
    numbers and flags empty is definitionally unset one layer down.

    THE TWO ARE REPORTED SEPARATELY, which is the part that earns its keep: an
    absent variable says "nothing set this", and an empty one says "something
    set this to nothing", which is a different line to go and look at.
    """

    def test_an_empty_value_does_not_satisfy_a_requirement(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(REQUIRED_ENV, "POSTERN_REDIS_URL")
        monkeypatch.setenv("POSTERN_REDIS_URL", "")
        report = classify_environment("api")
        assert report.blank == ("POSTERN_REDIS_URL",)
        assert report.absent == ()

    def test_a_whitespace_only_value_does_not_either(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """What a YAML block scalar or a trailing-space env line produces.

        `bool_from_env` already strips before deciding, so a flag set to a
        newline is unset there too. `int_from_env` does NOT strip and would
        raise on ``"  "`` instead -- the two readers disagree about whitespace
        and that is left exactly as it is; this check reads no value for use, it
        only asks whether one arrived.
        """
        monkeypatch.setenv(REQUIRED_ENV, "POSTERN_REDIS_URL")
        monkeypatch.setenv("POSTERN_REDIS_URL", "  \n ")
        assert classify_environment("api").blank == ("POSTERN_REDIS_URL",)

    def test_absent_and_empty_are_never_both_reported_for_one_name(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(REQUIRED_ENV, "POSTERN_REDIS_URL,POSTERN_JWKS_URI")
        monkeypatch.setenv("POSTERN_REDIS_URL", "")
        report = classify_environment("api")
        assert report.blank == ("POSTERN_REDIS_URL",)
        assert report.absent == ("POSTERN_JWKS_URI",)

    def test_a_value_of_zero_or_false_still_satisfies_it(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The requirement is about ARRIVAL, never about what the value says.

        ``POSTERN_REQUIRE_REDIS=0`` is an operator deliberately turning a switch
        off, and a check that called that unsatisfied would be second-guessing a
        decision it cannot see the reasons for.
        """
        monkeypatch.setenv(REQUIRED_ENV, "POSTERN_REQUIRE_REDIS,POSTERN_TRUSTED_PROXY_HOPS")
        monkeypatch.setenv("POSTERN_REQUIRE_REDIS", "0")
        monkeypatch.setenv("POSTERN_TRUSTED_PROXY_HOPS", "0")
        report = classify_environment("api")
        assert report.absent == ()
        assert report.blank == ()


class TestTheRequirementListIsCheckedAgainstTheInventory:
    """A requirement naming a variable nothing reads can never be met usefully."""

    def test_a_name_in_no_inventory_is_unsatisfiable(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(REQUIRED_ENV, "POSTERN_REQUIRE_REDDIS")
        (bad,) = classify_environment("api").unsatisfiable
        assert bad.name == "POSTERN_REQUIRE_REDDIS"
        assert bad.suggestion == "POSTERN_REQUIRE_REDIS"

    def test_it_is_unsatisfiable_whether_or_not_the_variable_is_also_set(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """THE TWO HALVES OF THIS GUARD COMPOSE, and this is where.

        A typo in the requirement list is caught either way. Set the misspelt
        variable and the unread-name half refuses it; leave it unset and that
        half is silent by design -- an unset variable is invisible to it -- and
        this half refuses the requirement instead. Neither alone covers both.
        """
        monkeypatch.setenv(REQUIRED_ENV, "POSTERN_REQUIRE_REDDIS")
        unset = classify_environment("api")
        assert [u.name for u in unset.unsatisfiable] == ["POSTERN_REQUIRE_REDDIS"]
        assert unset.unknown == ()

        monkeypatch.setenv("POSTERN_REQUIRE_REDDIS", "1")
        both = classify_environment("api")
        assert [u.name for u in both.unsatisfiable] == ["POSTERN_REQUIRE_REDDIS"]
        assert [u.name for u in both.unknown] == ["POSTERN_REQUIRE_REDDIS"]

    def test_the_hatch_does_not_make_a_requirement_satisfiable(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Declaring a name as one Postern ignores cannot also make it required.

        The two lists mean opposite things, and an operator who put a name in
        both has said something contradictory. `ALLOWED_UNREAD_ENV` stops the
        variable being refused as unread; it cannot put the name in `INVENTORY`,
        which is what a requirement needs.
        """
        monkeypatch.setenv("POSTERN_SIDECAR_SCRAPE_TOKEN", "x")
        monkeypatch.setenv(ALLOWED_UNREAD_ENV, "POSTERN_SIDECAR_SCRAPE_TOKEN")
        monkeypatch.setenv(REQUIRED_ENV, "POSTERN_SIDECAR_SCRAPE_TOKEN")
        report = classify_environment("api")
        assert report.unknown == ()
        assert [u.name for u in report.unsatisfiable] == ["POSTERN_SIDECAR_SCRAPE_TOKEN"]

    def test_no_wildcards(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(REQUIRED_ENV, "POSTERN_REQUIRE_*")
        assert len(classify_environment("api").unsatisfiable) == 1


class TestRequiringAVariableTheOtherServiceReads:
    """POPULATION 2 AGAIN, and the same ruling for the same reason.

    One ``POSTERN_REQUIRED_ENV`` listing everything both deployables need is
    what an operator with one environment file will write. Refusing the api
    service because a confirm-only variable is absent from ITS environment would
    be a crash loop on a correct deployment, so a requirement this service
    cannot read is reported and never fatal.

    WHAT THAT COSTS, stated rather than hidden: a dropped key belonging to the
    other service is not caught here. An operator who wants it caught writes one
    requirement list per service, which is the deployment shape that can
    distinguish the two in the first place.
    """

    def test_it_is_reported_and_never_fatal(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(REQUIRED_ENV, "POSTERN_CONFIRM_MAX_BODY_BYTES")
        report = classify_environment("api")
        assert report.absent == ()
        assert report.unsatisfiable == ()
        assert report.unenforceable == ("POSTERN_CONFIRM_MAX_BODY_BYTES",)
        enforce_known_environment(service="api")

    def test_the_service_that_does_read_it_enforces_it(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The same list, the same missing variable, the other deployable."""
        monkeypatch.setenv(REQUIRED_ENV, "POSTERN_CONFIRM_MAX_BODY_BYTES")
        report = classify_environment("confirm")
        assert report.absent == ("POSTERN_CONFIRM_MAX_BODY_BYTES",)
        assert report.unenforceable == ()


class TestWhatTheRequirementRefusalSays:
    def test_an_absent_variable_refuses_naming_it(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(REQUIRED_ENV, "POSTERN_REQUIRE_REDIS")
        with pytest.raises(RuntimeError) as raised:
            enforce_known_environment(service="api")
        message = str(raised.value)
        assert "POSTERN_REQUIRE_REDIS" in message
        assert REQUIRED_ENV in message

    def test_an_empty_variable_says_something_set_it_to_nothing(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(REQUIRED_ENV, "POSTERN_REDIS_URL")
        monkeypatch.setenv("POSTERN_REDIS_URL", "")
        with pytest.raises(RuntimeError) as raised:
            enforce_known_environment(service="api")
        message = str(raised.value)
        assert "POSTERN_REDIS_URL" in message
        assert "empty" in message

    def test_one_refusal_carries_every_finding(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """An operator fixing one class at a time redeploys once per class."""
        monkeypatch.setenv("POSTERN_REQUIRE_REDDIS", "1")
        monkeypatch.setenv(REQUIRED_ENV, "POSTERN_REQUIRE_REDIS,POSTERN_JWKS_URI,POSTERN_NONSENSE")
        monkeypatch.setenv("POSTERN_JWKS_URI", "")
        with pytest.raises(RuntimeError) as raised:
            enforce_known_environment(service="api")
        message = str(raised.value)
        for expected in (
            "POSTERN_REQUIRE_REDDIS",
            "POSTERN_REQUIRE_REDIS",
            "POSTERN_JWKS_URI",
            "POSTERN_NONSENSE",
        ):
            assert expected in message, expected

    def test_a_satisfied_list_raises_nothing(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(REQUIRED_ENV, "POSTERN_REQUIRE_REDIS,POSTERN_REDIS_URL")
        monkeypatch.setenv("POSTERN_REQUIRE_REDIS", "1")
        monkeypatch.setenv("POSTERN_REDIS_URL", "redis://localhost:6379/0")
        enforce_known_environment(service="api")


class TestTheRequirementListIsItselfInTheInventory:
    def test_it_is_read_by_every_service(self) -> None:
        """Or the guard would refuse the variable that configures it."""
        assert REQUIRED_ENV in KNOWN_ENV
        for service in sorted(SERVICES):
            assert REQUIRED_ENV in names_read_by(service)

    def test_a_misspelt_requirement_list_fails_loudly(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The same property the hatch has: a wrong list cannot fail quiet.

        Misspelling it means no requirement is declared, which on its own is
        silent -- the whole weakness of a list that lives in the environment.
        What is NOT silent is the misspelt name itself: it is an unread
        ``POSTERN_`` variable, so the unread half refuses and names this one as
        the nearest name that is read.
        """
        monkeypatch.setenv("POSTERN_REQUIRED_EVN", "POSTERN_REQUIRE_REDIS")
        with pytest.raises(RuntimeError) as raised:
            enforce_known_environment(service="api")
        message = str(raised.value)
        assert "POSTERN_REQUIRED_EVN" in message
        assert REQUIRED_ENV in message


class TestMigrationsRunTheGuardToo:
    """``alembic upgrade`` is the third caller, and the worst place for a typo.

    WHY IT MATTERS MORE HERE THAN IN EITHER SERVICE. `migrations/env.py` applies
    ``POSTERN_DATABASE_URL`` over ``alembic.ini``'s ``sqlalchemy.url`` only when
    the variable is SET, so a misspelt name leaves the ini file's URL in place
    and the migration applies DDL to whatever that names. In this repository the
    ini file carries the generated placeholder
    ``driver://user:pass@localhost/dbname``, so the failure happens to be loud;
    an operator who put a real URL there -- the ordinary way to use alembic --
    gets a migration against the wrong database and no sign that it happened.

    DRIVEN AS A SUBPROCESS, not by importing `migrations/env.py`. That module
    runs migrations at import, so importing it in-process is not a test but a
    deployment. The guard fires while alembic is still loading ``env.py``, before
    any engine is built, so no database is reached either way and the case needs
    no fixture.
    """

    @staticmethod
    def _alembic(**env: str) -> subprocess.CompletedProcess[str]:
        repo = Path(__file__).resolve().parent.parent
        environment = {k: v for k, v in os.environ.items() if not k.upper().startswith("POSTERN_")}
        environment.update(env)
        return subprocess.run(  # noqa: S603
            # `sys.executable` rather than a bare "alembic": an absolute path,
            # already inside this venv, and no dependency on what is on PATH.
            [sys.executable, "-m", "alembic", "upgrade", "head"],
            cwd=repo,
            env=environment,
            capture_output=True,
            text=True,
            check=False,
        )

    def test_a_misspelt_database_url_stops_the_migration(self) -> None:
        done = self._alembic(POSTERN_DATABASE_UR="postgresql+asyncpg://u:p@db/x")
        assert done.returncode != 0
        assert "POSTERN_DATABASE_UR" in done.stderr
        assert "Did you mean POSTERN_DATABASE_URL?" in done.stderr

    def test_it_refuses_before_reaching_any_database(self) -> None:
        """The refusal is the whole output, not a symptom found after connecting.

        If the guard ran after the engine were built, a stray variable would
        surface as whatever the connection did first. Asserting on the absence of
        a connection error is what pins the ORDER.
        """
        done = self._alembic(POSTERN_DATABASE_UR="postgresql+asyncpg://u:p@db/x")
        assert "no code in this deployment reads" in done.stderr
        for connection_noise in ("could not translate", "Connection refused", "asyncpg"):
            assert connection_noise not in done.stderr

    def test_a_requirement_the_migration_cannot_meet_stops_it_too(self) -> None:
        """``POSTERN_REQUIRED_ENV`` is read here as well, and enforced here."""
        done = self._alembic(**{REQUIRED_ENV: "POSTERN_DATABASE_URL"})
        assert done.returncode != 0
        assert "POSTERN_DATABASE_URL" in done.stderr
        assert REQUIRED_ENV in done.stderr

    def test_a_service_only_requirement_does_not_stop_it(self) -> None:
        """One requirement list across all three callers must not break the third.

        ``POSTERN_REQUIRE_REDIS`` is not read by the migration task, so requiring
        it is reported there and never fatal -- the same ruling population 2 got,
        and it is what lets an operator keep one list.
        """
        done = self._alembic(
            POSTERN_DATABASE_URL="postgresql+asyncpg://postern:postern@127.0.0.1:1/postern",
            **{REQUIRED_ENV: "POSTERN_REQUIRE_REDIS"},
        )
        assert "POSTERN_REQUIRED_ENV" not in done.stderr or "does not read" in done.stderr
        assert "no code in this deployment reads" not in done.stderr

    def test_it_claims_to_be_the_migration_and_not_the_read_path(self) -> None:
        """The ``service`` argument, which no module path can pin.

        `tests/test_settings_bounds.py`'s attribution test derives which
        deployable reads a variable from where the READ is, so it says nothing
        about which name a CALLER passes. A migration claiming ``service="api"``
        would pass every check in this repository while enforcing the read path's
        requirements and warning about nothing -- so it is pinned on behaviour
        instead: ``POSTERN_CACHE_TTL_SECONDS`` is read by `services/api` and by
        nothing else, so the migration must report it unread. Claiming to be the
        api service would make that line disappear.
        """
        done = self._alembic(
            POSTERN_DATABASE_URL="postgresql+asyncpg://postern:postern@127.0.0.1:1/postern",
            POSTERN_CACHE_TTL_SECONDS="60",
        )
        assert "POSTERN_CACHE_TTL_SECONDS" in done.stderr
        assert "does not read" in done.stderr

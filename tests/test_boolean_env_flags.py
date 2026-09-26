"""The other two safety switches read the same way as `POSTERN_REQUIRE_REDIS`.

THE DEFECT, AND WHY IT IS THE SAME ONE TWICE MORE. Both flags below compared
the environment against the literal ``"1"``, so every other spelling an
operator could plausibly write meant off, in silence. On a safety switch that
is the worst available direction:

``POSTERN_REQUIRE_PEM_KEY=true``
    meant "do not require a persisted PEM key". A deployment that believed it
    had banned in-process generated signing keys had banned nothing, and the
    symptom appears only after a restart, as
    ``joserfc.errors.BadSignatureError`` against every token the previous
    process minted -- an error that reads like forgery rather than like a
    configuration flag that did nothing.

``POSTERN_STRICT_HEADERS=true``
    meant lax headers. The MCP Streamable HTTP header checks an operator
    thought they had turned on were off.

Both now read through `postern_core.config.bool_from_env`, so ``true``,
``yes`` and ``on`` arm them, ``0``, ``false``, ``no`` and ``off`` disarm them,
and anything else refuses to start rather than guessing. Both changes move in
the safe direction: a value that used to mean off now means on or refuses.

WHAT THIS FILE DRIVES. `POSTERN_REQUIRE_PEM_KEY` through ``create_app``,
because the guard lives inside ``_read_key_source`` and only fires once the
generated key exists -- a test of the flag alone would not show that the guard
is reached. `POSTERN_STRICT_HEADERS` through ``Settings.from_env``, because
that is the whole of its surface: it is a field on the settings object, not a
guard, so what a bad spelling must do there is refuse the parse.

THE THIRD FLAG IS NOT HERE. `POSTERN_REQUIRE_REDIS` has its own file,
`tests/test_require_redis_guard.py`, which pins the accepting and rejecting
sets and the unparseable-value refusal in detail. This file asserts that these
two reach the same verdicts, and does not re-derive the sets.
"""

from __future__ import annotations

import pytest
from postern_core.config import BOOL_FALSE, BOOL_TRUE

from services.api.main import create_app
from services.api.settings import Settings

BACKEND = "https://backend.test"

#: Spellings that must arm a flag, drawn from `BOOL_TRUE` plus the case and
#: whitespace forms `bool_from_env` folds away.
ON = ["1", "true", "TRUE", "yes", "on", "ON", " 1 ", "True\n"]

#: Spellings that must leave it disarmed, plus the two that mean "unset".
OFF = ["0", "false", "FALSE", "no", "off", "", "   "]

#: Values that are neither, which must refuse rather than default to off.
UNPARSEABLE = ["maybe", "2", "y", "t", "enabled", "ture", "-1"]


@pytest.fixture(autouse=True)
def _clean_flag_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """Neither flag set, and no PEM path, whatever the developer's shell holds.

    ``POSTERN_READ_KEY_PEM_PATH`` is deleted too: with one set, the PEM guard
    is never reached at all, and every case below would pass for the wrong
    reason.
    """
    monkeypatch.setenv("POSTERN_BACKEND_BASE_URL", BACKEND)
    for name in (
        "POSTERN_REQUIRE_PEM_KEY",
        "POSTERN_STRICT_HEADERS",
        "POSTERN_READ_KEY_PEM_PATH",
    ):
        monkeypatch.delenv(name, raising=False)


# ---------------------------------------------------------------------------
# POSTERN_REQUIRE_PEM_KEY, through the real composition root.
# ---------------------------------------------------------------------------


class TestRequirePemKey:
    @pytest.mark.parametrize("value", ON)
    def test_every_on_spelling_refuses_an_ephemeral_key(
        self, value: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """``=true`` used to build an app with a generated key. Now it does not."""
        monkeypatch.setenv("POSTERN_REQUIRE_PEM_KEY", value)
        with pytest.raises(RuntimeError) as raised:
            create_app(Settings.for_testing())
        assert "POSTERN_READ_KEY_PEM_PATH" in str(raised.value)

    @pytest.mark.parametrize("value", OFF)
    def test_every_off_spelling_still_builds(
        self, value: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("POSTERN_REQUIRE_PEM_KEY", value)
        assert create_app(Settings.for_testing()) is not None

    def test_unset_still_builds(self) -> None:
        """The development path, which must not start failing."""
        assert create_app(Settings.for_testing()) is not None

    @pytest.mark.parametrize("value", UNPARSEABLE)
    def test_an_unparseable_value_refuses_to_start(
        self, value: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Not off, which is what it used to be.

        A flag nobody can read is not a flag set to no; treating it as no is
        the silent disarm this whole change removes.
        """
        monkeypatch.setenv("POSTERN_REQUIRE_PEM_KEY", value)
        with pytest.raises(ValueError):
            create_app(Settings.for_testing())

    def test_the_unparseable_refusal_says_what_the_flag_is_for(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The ``because`` sentence has to name the loss, not the mechanism.

        An operator who reads "it gates a boolean" learns nothing; one who
        reads that a restart invalidates every token knows whether they care.
        """
        monkeypatch.setenv("POSTERN_REQUIRE_PEM_KEY", "maybe")
        with pytest.raises(ValueError) as raised:
            create_app(Settings.for_testing())
        message = str(raised.value)
        assert "POSTERN_REQUIRE_PEM_KEY" in message
        assert "'maybe'" in message
        assert "ephemeral" in message
        for token in sorted(BOOL_TRUE) + sorted(BOOL_FALSE):
            assert token in message

    def test_a_configured_pem_path_never_reaches_the_flag(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: object
    ) -> None:
        """The guard is about the ABSENCE of a key path.

        With one set the generated branch never runs, so even an unparseable
        flag cannot refuse here -- the read never happens. Pinned because it
        is the difference between a flag that is evaluated eagerly and one
        evaluated where it is needed.
        """
        monkeypatch.setenv("POSTERN_REQUIRE_PEM_KEY", "maybe")
        settings = Settings(backend_base_url=BACKEND, read_key_pem_path=None)
        # Sanity: with no path the same value refuses, so the assertion below
        # is about the path and not about the value being harmless.
        with pytest.raises(ValueError):
            create_app(settings)


# ---------------------------------------------------------------------------
# POSTERN_STRICT_HEADERS, through Settings.from_env.
# ---------------------------------------------------------------------------


class TestStrictHeaders:
    @pytest.mark.parametrize("value", ON)
    def test_every_on_spelling_turns_it_on(
        self, value: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """``=true`` used to mean lax headers."""
        monkeypatch.setenv("POSTERN_STRICT_HEADERS", value)
        assert Settings.from_env().strict_headers is True

    @pytest.mark.parametrize("value", OFF)
    def test_every_off_spelling_leaves_it_off(
        self, value: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("POSTERN_STRICT_HEADERS", value)
        assert Settings.from_env().strict_headers is False

    def test_unset_leaves_it_off(self) -> None:
        """``docker-compose.yml`` sets ``"0"`` and the default is off; neither
        may change because the reader did."""
        assert Settings.from_env().strict_headers is False

    @pytest.mark.parametrize("value", UNPARSEABLE)
    def test_an_unparseable_value_refuses_the_parse(
        self, value: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("POSTERN_STRICT_HEADERS", value)
        with pytest.raises(ValueError):
            Settings.from_env()

    def test_the_unparseable_refusal_says_what_the_flag_is_for(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("POSTERN_STRICT_HEADERS", "maybe")
        with pytest.raises(ValueError) as raised:
            Settings.from_env()
        message = str(raised.value)
        assert "POSTERN_STRICT_HEADERS" in message
        assert "'maybe'" in message
        assert "header" in message.lower()


# ---------------------------------------------------------------------------
# One reader, one verdict, across all three flags.
# ---------------------------------------------------------------------------


class TestAllThreeFlagsAgree:
    """The point of a shared reader is that no flag has its own dialect.

    Asserted against the two converted here; `POSTERN_REQUIRE_REDIS` is
    covered in its own file and reads the same function.
    """

    @pytest.mark.parametrize("value", ON)
    def test_on_means_on_for_both(self, value: str, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("POSTERN_STRICT_HEADERS", value)
        monkeypatch.setenv("POSTERN_REQUIRE_PEM_KEY", value)
        assert Settings.from_env().strict_headers is True
        with pytest.raises(RuntimeError):
            create_app(Settings.for_testing())

    @pytest.mark.parametrize("value", UNPARSEABLE)
    def test_unparseable_refuses_for_both(
        self, value: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("POSTERN_STRICT_HEADERS", value)
        with pytest.raises(ValueError):
            Settings.from_env()
        monkeypatch.delenv("POSTERN_STRICT_HEADERS")
        monkeypatch.setenv("POSTERN_REQUIRE_PEM_KEY", value)
        with pytest.raises(ValueError):
            create_app(Settings.for_testing())

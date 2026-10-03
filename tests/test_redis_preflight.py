"""Startup refusal on Redis clock skew and on an evicting ``maxmemory-policy``.

Three layers: the two checks against a scripted client (patching the module's
local time source, never Redis), the same checks against real Redis (the
shared session container for the passing and skew cases; a PRIVATE container
for every case that needs a different server configuration, because the policy
on the shared one must never change), and both composition roots.
"""

from __future__ import annotations

import dataclasses
import logging
from collections.abc import Iterator
from typing import Any

import docker
import pytest
import redis
from docker.errors import DockerException
from fastmcp.server.auth.providers.jwt import JWTVerifier, RSAKeyPair
from postern_core.auth import redis_preflight
from postern_core.auth.redis_preflight import (
    RedisPreflightError,
    check_clock_skew,
    check_eviction_policy,
    run_redis_preflight,
)
from postern_core.auth.revocation import PAIR_IAT_TOLERANCE_MS
from redis.exceptions import ConnectionError as RedisConnectionError
from redis.exceptions import ResponseError
from testcontainers.community.redis import RedisContainer

from services.api.main import create_app
from services.api.settings import Settings
from services.confirm.device_auth import APPROVAL_CLOCK_TOLERANCE_MS
from services.confirm.main import create_confirm_app
from services.confirm.settings import ConfirmSettings
from tests.test_device_grant import AUDIENCE, ISSUER


class FakeClock:
    """A local clock that advances by `step_ms` on every read."""

    def __init__(self, now_ms: float, step_ms: float = 0.0) -> None:
        self.now_ms = now_ms
        self.step_ms = step_ms

    def __call__(self) -> float:
        value = self.now_ms
        self.now_ms += self.step_ms
        return value


class ScriptedRedis:
    """Just the three calls the checks make."""

    def __init__(
        self,
        *,
        time_ms: float = 0.0,
        policy: str | None = "noeviction",
        config_error: Exception | None = None,
        time_error: Exception | None = None,
    ) -> None:
        self.time_ms = time_ms
        self.policy = policy
        self.config_error = config_error
        self.time_error = time_error
        self.calls: list[str] = []
        self.closed = False

    def time(self) -> tuple[int, int]:
        self.calls.append("TIME")
        if self.time_error:
            raise self.time_error
        return int(self.time_ms // 1000), int((self.time_ms % 1000) * 1000)

    def config_get(self, name: str) -> dict[str, str]:
        self.calls.append(f"CONFIG GET {name}")
        if self.config_error:
            raise self.config_error
        return {} if self.policy is None else {name: self.policy}

    def close(self) -> None:
        self.closed = True


BASE_MS = 1_800_000_000_000.0


def _local(monkeypatch: pytest.MonkeyPatch, now_ms: float, step_ms: float = 0.0) -> None:
    monkeypatch.setattr(redis_preflight, "_wall_ms", FakeClock(now_ms, step_ms))


class TestTheToleranceIsTheExistingConstant:
    def test_the_default_is_the_pair_floor_tolerance(self) -> None:
        assert PAIR_IAT_TOLERANCE_MS == 2_000

    def test_confirms_constant_is_the_same_number(self) -> None:
        assert APPROVAL_CLOCK_TOLERANCE_MS == PAIR_IAT_TOLERANCE_MS


class TestClockSkew:
    def test_no_skew_passes(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _local(monkeypatch, BASE_MS)
        check_clock_skew(ScriptedRedis(time_ms=BASE_MS))

    def test_one_second_either_way_passes(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _local(monkeypatch, BASE_MS)
        check_clock_skew(ScriptedRedis(time_ms=BASE_MS + 1_000))
        check_clock_skew(ScriptedRedis(time_ms=BASE_MS - 1_000))

    def test_exactly_at_the_tolerance_passes(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _local(monkeypatch, BASE_MS)
        check_clock_skew(ScriptedRedis(time_ms=BASE_MS + 2_000))

    def test_three_seconds_ahead_refuses(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _local(monkeypatch, BASE_MS)
        with pytest.raises(RedisPreflightError) as raised:
            check_clock_skew(ScriptedRedis(time_ms=BASE_MS + 3_000))
        message = str(raised.value)
        assert "clock-skew" in message
        assert "3000 ms ahead" in message
        assert "2000 ms" in message
        assert "NTP" in message

    def test_three_seconds_behind_refuses(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _local(monkeypatch, BASE_MS)
        with pytest.raises(RedisPreflightError, match="3000 ms behind"):
            check_clock_skew(ScriptedRedis(time_ms=BASE_MS - 3_000))

    def test_a_tolerance_argument_is_honoured(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _local(monkeypatch, BASE_MS)
        with pytest.raises(RedisPreflightError):
            check_clock_skew(ScriptedRedis(time_ms=BASE_MS + 600), tolerance_ms=500)

    def test_a_slow_round_trip_does_not_refuse_a_healthy_deployment(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Redis read its clock at the midpoint of a 1.8 s round trip."""
        _local(monkeypatch, BASE_MS, step_ms=1_800)
        check_clock_skew(ScriptedRedis(time_ms=BASE_MS + 900))

    def test_the_interval_is_allowed_for_before_refusing(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Estimated skew 2.9 s, but a 2 s round trip means 1.9 s is possible."""
        _local(monkeypatch, BASE_MS, step_ms=2_000)
        check_clock_skew(ScriptedRedis(time_ms=BASE_MS + 1_000 + 2_900))

    def test_a_real_three_second_skew_is_not_hidden_by_a_fast_round_trip(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _local(monkeypatch, BASE_MS, step_ms=50)
        with pytest.raises(RedisPreflightError):
            check_clock_skew(ScriptedRedis(time_ms=BASE_MS + 25 + 3_000))

    def test_a_round_trip_over_half_the_tolerance_warns_once(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        _local(monkeypatch, BASE_MS, step_ms=1_200)
        with caplog.at_level(logging.WARNING, logger=redis_preflight.logger.name):
            check_clock_skew(ScriptedRedis(time_ms=BASE_MS + 600))
        warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
        assert len(warnings) == 1
        assert "inconclusive" in warnings[0].getMessage()

    def test_a_fast_round_trip_does_not_warn(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        _local(monkeypatch, BASE_MS, step_ms=900)
        with caplog.at_level(logging.WARNING, logger=redis_preflight.logger.name):
            check_clock_skew(ScriptedRedis(time_ms=BASE_MS + 450))
        assert not [r for r in caplog.records if r.levelno == logging.WARNING]

    def test_a_connection_error_propagates(self) -> None:
        with pytest.raises(RedisConnectionError):
            check_clock_skew(ScriptedRedis(time_error=RedisConnectionError("down")))


class TestEvictionPolicy:
    def test_noeviction_passes(self) -> None:
        check_eviction_policy(ScriptedRedis(policy="noeviction"))

    @pytest.mark.parametrize(
        "policy", ["allkeys-lru", "volatile-lru", "allkeys-lfu", "volatile-ttl", "allkeys-random"]
    )
    def test_an_evicting_policy_refuses(self, policy: str) -> None:
        with pytest.raises(RedisPreflightError) as raised:
            check_eviction_policy(ScriptedRedis(policy=policy))
        message = str(raised.value)
        assert "maxmemory-policy" in message
        assert repr(policy) in message
        assert "noeviction" in message

    def test_a_config_refusal_warns_once_and_continues(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        client = ScriptedRedis(config_error=ResponseError("unknown command 'CONFIG'"))
        with caplog.at_level(logging.WARNING, logger=redis_preflight.logger.name):
            check_eviction_policy(client)
        warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
        assert len(warnings) == 1
        assert "cannot be verified" in warnings[0].getMessage()
        assert "noeviction" in warnings[0].getMessage()

    def test_an_empty_reply_warns_once_and_continues(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        with caplog.at_level(logging.WARNING, logger=redis_preflight.logger.name):
            check_eviction_policy(ScriptedRedis(policy=None))
        assert len([r for r in caplog.records if r.levelno == logging.WARNING]) == 1

    def test_a_connection_error_propagates(self) -> None:
        with pytest.raises(RedisConnectionError):
            check_eviction_policy(ScriptedRedis(config_error=RedisConnectionError("down")))


class TestRunPreflight:
    def test_no_url_makes_no_redis_call(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("POSTERN_REDIS_URL", raising=False)

        def boom(url: str) -> Any:
            raise AssertionError("a client was built without a Redis URL")

        monkeypatch.setattr(redis_preflight, "_client_from_url", boom)
        run_redis_preflight()

    def test_a_blank_url_makes_no_redis_call(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("POSTERN_REDIS_URL", "  ")
        monkeypatch.setattr(redis_preflight, "_client_from_url", lambda url: 1 / 0)
        run_redis_preflight()

    def test_runs_both_checks_and_closes_the_client(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("POSTERN_REDIS_URL", "redis://x:1/0")
        client = ScriptedRedis(time_ms=BASE_MS)
        monkeypatch.setattr(redis_preflight, "_client_from_url", lambda url: client)
        _local(monkeypatch, BASE_MS)
        run_redis_preflight()
        assert client.calls == ["TIME", "CONFIG GET maxmemory-policy"]
        assert client.closed

    def test_closes_the_client_when_a_check_refuses(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("POSTERN_REDIS_URL", "redis://x:1/0")
        client = ScriptedRedis(time_ms=BASE_MS + 9_000)
        monkeypatch.setattr(redis_preflight, "_client_from_url", lambda url: client)
        _local(monkeypatch, BASE_MS)
        with pytest.raises(RedisPreflightError):
            run_redis_preflight()
        assert client.closed

    def test_an_unreachable_redis_fails_startup(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("POSTERN_REDIS_URL", "redis://127.0.0.1:1/0")
        with pytest.raises(RedisConnectionError):
            run_redis_preflight()


# ---------------------------------------------------------------------------
# Real Redis.
# ---------------------------------------------------------------------------


@pytest.fixture()
def sync_client(redis_url: str) -> Iterator[redis.Redis]:
    client = redis.Redis.from_url(redis_url, decode_responses=True)
    yield client
    client.close()


class TestAgainstRealRedis:
    def test_the_shared_redis_passes_both_checks(self, sync_client: redis.Redis) -> None:
        check_clock_skew(sync_client)
        check_eviction_policy(sync_client)

    def test_a_local_clock_five_seconds_behind_redis_refuses(
        self, sync_client: redis.Redis, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        real = redis_preflight._wall_ms
        monkeypatch.setattr(redis_preflight, "_wall_ms", lambda: real() - 5_000)
        with pytest.raises(RedisPreflightError, match="ahead of this host"):
            check_clock_skew(sync_client)

    def test_a_local_clock_five_seconds_ahead_of_redis_refuses(
        self, sync_client: redis.Redis, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        real = redis_preflight._wall_ms
        monkeypatch.setattr(redis_preflight, "_wall_ms", lambda: real() + 5_000)
        with pytest.raises(RedisPreflightError, match="behind this host"):
            check_clock_skew(sync_client)


def _private_redis(command: str) -> Iterator[str]:
    try:
        docker.from_env().ping()
    except DockerException as exc:
        pytest.skip(f"Docker is not reachable, skipping Redis-backed tests: {exc}")
    with RedisContainer("redis:7-alpine").with_command(command) as container:
        host = container.get_container_host_ip()
        yield f"redis://{host}:{container.get_exposed_port(6379)}/0"


@pytest.fixture(scope="module")
def evicting_redis_url() -> Iterator[str]:
    """A PRIVATE container started with an evicting policy."""
    yield from _private_redis("redis-server --maxmemory-policy allkeys-lru")


@pytest.fixture(scope="module")
def config_disabled_redis_url() -> Iterator[str]:
    """A PRIVATE container on which CONFIG does not exist, as on managed Redis."""
    yield from _private_redis('redis-server --rename-command CONFIG ""')


class TestAgainstARedisConfiguredWrong:
    def test_allkeys_lru_refuses(self, evicting_redis_url: str) -> None:
        client = redis.Redis.from_url(evicting_redis_url, decode_responses=True)
        try:
            with pytest.raises(RedisPreflightError, match="'allkeys-lru'"):
                check_eviction_policy(client)
        finally:
            client.close()

    def test_run_preflight_refuses_it_end_to_end(
        self, evicting_redis_url: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("POSTERN_REDIS_URL", evicting_redis_url)
        with pytest.raises(RedisPreflightError, match="eviction-policy"):
            run_redis_preflight()

    def test_a_disabled_config_warns_once_and_starts(
        self,
        config_disabled_redis_url: str,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        monkeypatch.setenv("POSTERN_REDIS_URL", config_disabled_redis_url)
        with caplog.at_level(logging.WARNING, logger=redis_preflight.logger.name):
            run_redis_preflight()
        assert len([r for r in caplog.records if r.levelno == logging.WARNING]) == 1


# ---------------------------------------------------------------------------
# The composition roots.
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def key_pair() -> RSAKeyPair:
    return RSAKeyPair.generate()


def _confirm(key_pair: RSAKeyPair, *, process_local: bool = False) -> Any:
    from postern_core.auth.device_keys import no_enrolled_devices

    return create_confirm_app(
        dataclasses.replace(
            ConfirmSettings.for_testing(), allow_process_local_sessions=process_local
        ),
        assertion_verifier=JWTVerifier(
            public_key=key_pair.public_key, issuer=ISSUER, audience=AUDIENCE
        ),
        device_key_store=no_enrolled_devices(),
    )


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("POSTERN_REDIS_URL", raising=False)
    monkeypatch.delenv("POSTERN_REQUIRE_REDIS", raising=False)


@pytest.fixture()
def counting_client(monkeypatch: pytest.MonkeyPatch) -> list[ScriptedRedis]:
    """Replace the preflight's client factory; every client built is recorded."""
    built: list[ScriptedRedis] = []

    def factory(url: str) -> ScriptedRedis:
        client = ScriptedRedis(time_ms=BASE_MS, policy="noeviction")
        built.append(client)
        return client

    monkeypatch.setattr(redis_preflight, "_client_from_url", factory)
    return built


class TestBothServicesRefuseToStart:
    def test_api_refuses_a_skewed_clock(
        self,
        counting_client: list[ScriptedRedis],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv("POSTERN_REDIS_URL", "redis://x:1/0")
        _local(monkeypatch, BASE_MS - 10_000)
        with pytest.raises(RedisPreflightError, match="clock-skew"):
            create_app(Settings.for_testing())

    def test_confirm_refuses_a_skewed_clock(
        self,
        key_pair: RSAKeyPair,
        counting_client: list[ScriptedRedis],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv("POSTERN_REDIS_URL", "redis://x:1/0")
        _local(monkeypatch, BASE_MS - 10_000)
        with pytest.raises(RedisPreflightError, match="clock-skew"):
            _confirm(key_pair)

    def test_api_refuses_an_evicting_policy(
        self, monkeypatch: pytest.MonkeyPatch, counting_client: list[ScriptedRedis]
    ) -> None:
        monkeypatch.setenv("POSTERN_REDIS_URL", "redis://x:1/0")
        monkeypatch.setattr(
            redis_preflight,
            "_client_from_url",
            lambda url: ScriptedRedis(time_ms=BASE_MS, policy="allkeys-lru"),
        )
        _local(monkeypatch, BASE_MS)
        with pytest.raises(RedisPreflightError, match="eviction-policy"):
            create_app(Settings.for_testing())

    def test_confirm_refuses_an_evicting_policy(
        self, key_pair: RSAKeyPair, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("POSTERN_REDIS_URL", "redis://x:1/0")
        monkeypatch.setattr(
            redis_preflight,
            "_client_from_url",
            lambda url: ScriptedRedis(time_ms=BASE_MS, policy="volatile-lru"),
        )
        _local(monkeypatch, BASE_MS)
        with pytest.raises(RedisPreflightError, match="eviction-policy"):
            _confirm(key_pair)

    def test_a_healthy_redis_starts_both(
        self,
        key_pair: RSAKeyPair,
        counting_client: list[ScriptedRedis],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv("POSTERN_REDIS_URL", "redis://x:1/0")
        _local(monkeypatch, BASE_MS)
        assert create_app(Settings.for_testing()) is not None
        assert _confirm(key_pair) is not None
        assert len(counting_client) == 2, "one preflight per service process"
        assert all(c.calls == ["TIME", "CONFIG GET maxmemory-policy"] for c in counting_client)

    def test_no_redis_url_changes_nothing_and_calls_no_redis(
        self,
        key_pair: RSAKeyPair,
        counting_client: list[ScriptedRedis],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        _local(monkeypatch, BASE_MS - 10_000)  # would refuse if anything looked
        assert create_app(Settings.for_testing()) is not None
        assert _confirm(key_pair, process_local=True) is not None
        assert counting_client == []


class TestApiRefusesBeforeAnythingIsBuilt:
    @pytest.mark.parametrize("fault", ["skew", "policy"])
    def test_nothing_downstream_is_called(
        self, fault: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("POSTERN_REDIS_URL", "redis://x:1/0")
        policy = "allkeys-lru" if fault == "policy" else "noeviction"
        monkeypatch.setattr(
            redis_preflight,
            "_client_from_url",
            lambda url: ScriptedRedis(time_ms=BASE_MS, policy=policy),
        )
        _local(monkeypatch, BASE_MS - (10_000 if fault == "skew" else 0))
        called: list[str] = []

        def tripwire(name: str) -> Any:
            def stub(*args: Any, **kwargs: Any) -> Any:
                called.append(name)
                raise AssertionError(f"{name} ran before the preflight")

            return stub

        for name in ("_read_key_source", "refuse_unverifiable_minter", "BackendClient", "Database"):
            monkeypatch.setattr(f"services.api.main.{name}", tripwire(name))
        with pytest.raises(RedisPreflightError):
            create_app(Settings.for_testing())
        assert called == []

"""The two Redis ACL users, driven by the real stores on a real Redis.

``dev-redis/users.acl`` is what ``docker-compose.yml`` loads into the stack's Redis.
Its grants were derived by reading the code; this file is the check that the
reading was complete. It starts a throwaway ``redis:7-alpine`` with that same
file (plus one extra line, a test-only admin, so ``ACL LOG`` can be read),
builds every Redis-backed store through ``__init__`` with the credentials
``docker-compose.yml`` gives each service, and calls the store methods the
services' code paths call. That is not every method of every store: the
operator-CLI-only revocation methods are left out on purpose, and a few
branches (a lost WATCH race) cannot be forced from here. What is covered is
checked by deleting grants from the ACL file one at a time and watching a test
fail; ``+discard`` is absent from the file because redis-py never sends
``DISCARD`` from any code path this repository uses. A command the code issues and the file does not
grant raises ``NOPERM`` here, in ``make ci``, and not in a deployment.

THE ASSERTION THAT CATCHES AN INCOMPLETE GRANT IS TWO-SIDED. Each flow runs
and then ``ACL LOG`` is read as the admin: it must be empty, because
``redis-py`` swallows some denials (``CLIENT SETINFO`` is the known one) and a
store method that catches ``Exception`` turns a ``NOPERM`` into its own
"unavailable" error. A denial that a flow absorbed still leaves a log entry.

The reverse is checked as well, because a grant that is too wide passes every
flow: each user is shown refused on the other service's keys, on the
destructive commands, and (for ``api``) on every write to the revocation list.

Plain TCP, not TLS: the ACL is the subject. The TLS listener is covered by the
live bring-up of the compose stack and by the static checks in
``tests/test_compose_redis_hardening.py``.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator, Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import docker
import pytest
import redis.asyncio as aioredis
import redis.exceptions
import yaml
from docker.errors import DockerException
from postern_core.auth.device_codes import RedisDeviceCodeStore, ScanClaim
from postern_core.auth.redis_preflight import run_redis_preflight
from postern_core.auth.refresh_sessions import (
    SESSION_ABSOLUTE_LIFETIME,
    RedisRefreshSessionStore,
    RefreshSession,
    Rotation,
    hash_refresh_token,
    new_refresh_token,
    new_sid,
)
from postern_core.auth.revocation import RedisRevocationStore
from postern_core.risk.context import RiskContext
from postern_core.risk.session import RedisSessionStore, SessionKey
from testcontainers.core.container import DockerContainer
from testcontainers.core.wait_strategies import LogMessageWaitStrategy

from services.confirm.customer_rate_limit import RedisCustomerRateLimitStore
from services.confirm.rate_limit import Limit

ROOT = Path(__file__).resolve().parent.parent
COMPOSE = yaml.safe_load((ROOT / "docker-compose.yml").read_text())
ADMIN = ("test_admin", "test-admin-pw")
KEY = SessionKey(customer_ref="cust_7f3a", client_id="vendor-a")


def _creds(service: str) -> tuple[str, str]:
    """The user and password ``docker-compose.yml`` hands ``service``."""
    parts = urlsplit(COMPOSE["services"][service]["environment"]["POSTERN_REDIS_URL"])
    assert parts.username is not None
    assert parts.password is not None
    return parts.username, parts.password


@pytest.fixture(scope="module")
def acl_redis(tmp_path_factory: pytest.TempPathFactory) -> Iterator[tuple[str, int]]:
    try:
        docker.from_env().ping()
    except DockerException as exc:
        pytest.skip(f"Docker is not reachable, skipping the Redis ACL tests: {exc}")
    acl = (ROOT / "dev-redis" / "users.acl").read_text()
    acl += f"\nuser {ADMIN[0]} on >{ADMIN[1]} ~* &* +@all\n"
    acl_file = tmp_path_factory.mktemp("redis-acl") / "users.acl"
    acl_file.write_text(acl)
    acl_file.chmod(0o644)
    container = (
        DockerContainer("redis:7-alpine")
        .with_command(
            "redis-server --save '' --appendonly no --aclfile /etc/redis/users.acl",
        )
        .with_volume_mapping(str(acl_file), "/etc/redis/users.acl", "ro")
        .with_exposed_ports(6379)
        .waiting_for(LogMessageWaitStrategy("Ready to accept connections"))
    )
    with container:
        yield container.get_container_host_ip(), int(container.get_exposed_port(6379))


def _connect(url: str, **kwargs: Any) -> Any:
    """``redis.asyncio.from_url``, which redis-py ships without annotations."""
    return aioredis.from_url(url, **kwargs)  # type: ignore[no-untyped-call]


def _url(acl_redis: tuple[str, int], who: tuple[str, str]) -> str:
    host, port = acl_redis
    return f"redis://{who[0]}:{who[1]}@{host}:{port}/0"


@pytest.fixture
def api_url(acl_redis: tuple[str, int]) -> str:
    return _url(acl_redis, _creds("api"))


@pytest.fixture
def confirm_url(acl_redis: tuple[str, int]) -> str:
    return _url(acl_redis, _creds("confirm"))


@pytest.fixture
async def admin(acl_redis: tuple[str, int]) -> AsyncIterator[Any]:
    client = _connect(_url(acl_redis, ADMIN), decode_responses=True)
    await client.acl_log_reset()
    yield client
    await client.aclose()


@pytest.fixture(autouse=True)
def _default_prefix(monkeypatch: pytest.MonkeyPatch) -> None:
    """``dev-redis/users.acl`` assumes the default prefix, so tests must use it."""
    monkeypatch.delenv("POSTERN_REDIS_KEY_PREFIX", raising=False)


async def _denials(admin: Any) -> list[str]:
    return [f"{e['username']}: {e['object']} ({e['reason']})" for e in await admin.acl_log()]


def _client(url: str) -> Any:
    return _connect(url, decode_responses=True)


# ---------------------------------------------------------------------------
# The default user and the other credentials.
# ---------------------------------------------------------------------------


class TestWhoGetsIn:
    async def test_no_credentials_is_refused(self, acl_redis: tuple[str, int]) -> None:
        host, port = acl_redis
        client = _connect(f"redis://{host}:{port}/0")
        with pytest.raises(redis.exceptions.AuthenticationError, match="Authentication required"):
            await client.ping()
        await client.aclose()

    async def test_default_user_with_a_password_is_refused(
        self, acl_redis: tuple[str, int]
    ) -> None:
        host, port = acl_redis
        client = _connect(f"redis://default:anything@{host}:{port}/0")
        with pytest.raises(redis.exceptions.AuthenticationError):
            await client.ping()
        await client.aclose()

    async def test_wrong_password_is_refused(self, acl_redis: tuple[str, int]) -> None:
        user, _ = _creds("api")
        client = _connect(_url(acl_redis, (user, "not-the-password")))
        with pytest.raises(
            redis.exceptions.AuthenticationError, match="invalid username-password pair"
        ):
            await client.ping()
        await client.aclose()

    async def test_the_two_services_cannot_log_in_as_each_other(
        self, acl_redis: tuple[str, int]
    ) -> None:
        api_user, _ = _creds("api")
        _, confirm_password = _creds("confirm")
        client = _connect(_url(acl_redis, (api_user, confirm_password)))
        with pytest.raises(redis.exceptions.AuthenticationError):
            await client.ping()
        await client.aclose()


# ---------------------------------------------------------------------------
# api: everything its code path issues, then nothing it should not.
# ---------------------------------------------------------------------------


class TestApiUser:
    async def test_every_command_the_api_issues_is_granted(
        self,
        acl_redis: tuple[str, int],
        api_url: str,
        confirm_url: str,
        admin: Any,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        # A session revocation written the way confirm writes it, and a
        # customer-client pair written by the operator's CLI (which confirm
        # does not hold the grants for: its SET and SADD of the pair stamps),
        # both read as api.
        confirm_revocations = RedisRevocationStore(url=confirm_url)
        await confirm_revocations.revoke_session(jti="tok-api-1")
        operator = RedisRevocationStore(url=_url(acl_redis, ADMIN))
        await operator.revoke_customer_client(customer_ref="cust_a", client_id="vendor")
        await operator.close()
        api_revocations = RedisRevocationStore(url=api_url)
        # RevocationMiddleware.dispatch: SISMEMBER x3 and GET of the pair floor,
        # in one non-transactional pipeline.
        claims = {"jti": "tok-api-1", "sub": "cust_a", "client_id": "vendor", "iat": 1}
        assert await api_revocations.is_revoked(claims) is True
        assert await api_revocations.is_revoked({"jti": "other", "sub": "z", "client_id": "q"}) is (
            False
        )

        # The risk-session store: load (GET, EXPIRE), save (SETEX), remove (DEL).
        sessions = RedisSessionStore(url=api_url, ttl=1800)
        await sessions.save(KEY, RiskContext(session_id=KEY.value))
        assert await sessions.load(KEY) is not None
        await sessions.remove(KEY)
        assert await sessions.load(KEY) is None

        # Startup preflight: TIME and CONFIG GET. A refused CONFIG is only a
        # warning in the code, so the log is asserted too.
        monkeypatch.setenv("POSTERN_REDIS_URL", api_url)
        with caplog.at_level(logging.WARNING):
            run_redis_preflight()
        assert "CONFIG was refused" not in caplog.text

        for store in (api_revocations, confirm_revocations, sessions):
            await store.close()
        assert await _denials(admin) == []

    async def test_api_cannot_write_the_revocation_list(self, api_url: str) -> None:
        client = _client(api_url)
        for command in (
            ("SADD", "postern:revoked:sessions", "x"),
            ("SREM", "postern:revoked:sessions", "x"),
            ("SET", "postern:revoked:pair-at:x", "1"),
            ("ZADD", "postern:revoked:sessions:exp", "1", "x"),
            ("DEL", "postern:revoked:sessions"),
            ("SMEMBERS", "postern:revoked:sessions"),
        ):
            with pytest.raises(redis.exceptions.NoPermissionError):
                await client.execute_command(*command)
        await client.aclose()

    async def test_api_cannot_touch_the_write_paths_keys(self, api_url: str) -> None:
        client = _client(api_url)
        for key in (
            "postern:device:abc",
            "postern:device:index",
            "postern:refresh:session:abc",
            "postern:ratelimit:customer:/token:x",
        ):
            for command in ("GET", "SET", "DEL"):
                args = (command, key) if command != "SET" else (command, key, "v")
                with pytest.raises(redis.exceptions.NoPermissionError):
                    await client.execute_command(*args)
        await client.aclose()

    async def test_api_cannot_run_destructive_or_administrative_commands(
        self, api_url: str
    ) -> None:
        client = _client(api_url)
        for command in (
            ("FLUSHALL",),
            ("FLUSHDB",),
            ("KEYS", "*"),
            ("SCAN", "0"),
            ("CONFIG", "SET", "maxmemory-policy", "allkeys-lru"),
            ("ACL", "LIST"),
            ("EVAL", "return 1", "0"),
            ("SHUTDOWN", "NOSAVE"),
        ):
            with pytest.raises(redis.exceptions.NoPermissionError):
                await client.execute_command(*command)
        await client.aclose()


# ---------------------------------------------------------------------------
# confirm: every method of every store its service builds.
# ---------------------------------------------------------------------------


def _in(seconds: int) -> datetime:
    return datetime.fromtimestamp(int(datetime.now(UTC).timestamp()) + seconds, UTC)


class TestConfirmUser:
    async def test_every_command_confirm_issues_is_granted(
        self,
        confirm_url: str,
        api_url: str,
        admin: Any,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        opened: list[Any] = []

        # --- device codes: create, the three lookups, scan, approve, consume,
        # revoke. Covers SET NX EX, ZREMRANGEBYSCORE, ZCARD, SETEX, ZADD, GET,
        # WATCH/MULTI/EXEC, DEL, ZREM and the compare-and-delete EVAL.
        codes = RedisDeviceCodeStore(url=confirm_url)
        opened.append(codes)
        code = await codes.create_device_code(
            client_id="vendor-a", scopes="accounts:read", verification_uri="https://bank.example/d"
        )
        assert await codes.get_device_code(code.device_code) is not None
        assert code.display_handle
        assert await codes.get_by_display_handle(code.display_handle) is not None
        assert await codes.get_by_user_code(code.user_code) is not None
        assert (
            await codes.claim_scan(code.device_code, "cust_7f3a", scanner_ip=None)
            is ScanClaim.CLAIMED
        )
        assert await codes.approve_scanned(code.device_code, "cust_7f3a") is True
        assert await codes.consume_device_code(code.device_code, session_id="s1") is True
        other = await codes.create_device_code(
            client_id="vendor-a", scopes="accounts:read", verification_uri="https://bank.example/d"
        )
        await codes.revoke_device_code(other.device_code)
        # claim_scan's CONFLICT_REVOKED branch deletes inside its MULTI.
        third = await codes.create_device_code(
            client_id="vendor-a", scopes="accounts:read", verification_uri="https://bank.example/d"
        )
        await codes.claim_scan(third.device_code, "cust_a", scanner_ip=None)
        await codes.claim_scan(third.device_code, "cust_b", scanner_ip=None)

        # --- refresh families: create, get, rotate, revoke, discard.
        refresh = RedisRefreshSessionStore(url=confirm_url)
        opened.append(refresh)
        sid = new_sid()
        token = new_refresh_token(sid)
        placeholder = datetime(2000, 1, 1, tzinfo=UTC)
        family = RefreshSession(
            sid=sid,
            customer_ref="cust_7f3a",
            client_id="claude-code",
            scopes="accounts:read",
            created_at=placeholder,
            expires_at=placeholder,
            generation=0,
            current_hash=hash_refresh_token(token),
            access_tokens=(("jti-0", _in(600)),),
            device_code_handle="0123456789abcdef",
        )
        assert SESSION_ABSOLUTE_LIFETIME > timedelta(0)
        await refresh.create(family)
        assert await refresh.get(sid) is not None
        rotated = await refresh.rotate(
            sid,
            presented_hash=hash_refresh_token(token),
            new_hash=hash_refresh_token("next"),
            access_jti="jti-1",
            access_expires_at=_in(600),
        )
        assert rotated.rotation is Rotation.ROTATED
        assert await refresh.revoke(sid, reason="test") is not None
        await refresh.discard(sid)

        # --- the revocation list: what the services call (revoke_session with
        # its in-line prune, is_revoked, is_customer_revoked,
        # customer_revoked_at) ...
        revocations = RedisRevocationStore(url=confirm_url)
        opened.append(revocations)
        await revocations.revoke_session(jti="tok-c-1")
        assert await revocations.is_revoked({"jti": "tok-c-1"}) is True
        assert await revocations.is_customer_revoked("cust_c") is False
        # Reads of the operator-owned sets and the pair floor stamp: SISMEMBER
        # on customer-clients and clients, and GET on revoked:pair-at.
        claims = {"jti": "j", "sub": "cust_c", "client_id": "vendor", "iat": 1}
        assert await revocations.is_revoked(claims) is False
        assert await revocations.customer_revoked_at("cust_c") is None

        # ... and the prune that removes an entry past its retention: the
        # Lua script's ZRANGEBYSCORE, SREM and ZREM, which only run when
        # there is something to remove. Retention 0 writes an entry that is
        # due at once.
        await revocations._revoke_session_for("tok-c-expired", 0)
        assert await revocations.prune_sessions() == 1
        assert await revocations.is_revoked({"jti": "tok-c-expired"}) is False

        # WATCH then an early return: redis-py sends UNWATCH on the way out.
        assert await codes.consume_device_code("no-such-device-code", session_id="s2") is False

        # --- the per-customer rate limit: SET NX EX, INCR, TTL.
        limiter = RedisCustomerRateLimitStore(url=confirm_url)
        opened.append(limiter)
        assert await limiter.charge("cust_7f3a", "/approve", Limit(5, 60)) is None

        # --- startup preflight.
        monkeypatch.setenv("POSTERN_REDIS_URL", confirm_url)
        with caplog.at_level(logging.WARNING):
            run_redis_preflight()
        assert "CONFIG was refused" not in caplog.text

        for store in opened:
            # The rate-limit store has no close() of its own.
            await (
                store._redis.aclose()
                if hasattr(store, "_redis") and not hasattr(store, "close")
                else store.close()
            )
        assert await _denials(admin) == []

    async def test_confirm_cannot_touch_the_apis_risk_keys(self, confirm_url: str) -> None:
        client = _client(confirm_url)
        for command in (
            ("GET", "postern:risk:x"),
            ("SETEX", "postern:risk:x", "60", "v"),
            ("DEL", "postern:risk:x"),
        ):
            with pytest.raises(redis.exceptions.NoPermissionError):
                await client.execute_command(*command)
        await client.aclose()

    async def test_confirm_cannot_delete_or_overwrite_a_revocation_entry(
        self, confirm_url: str
    ) -> None:
        """On the two session keys it may add and prune; elsewhere, read only.

        The write selector names ``revoked:sessions`` and ``revoked:sessions:exp``
        and nothing else. ``revoked:clients`` (the kill switch) and
        ``revoked:customer-clients`` are the operator's: confirm reads them
        through ``is_revoked`` and may not SADD or SREM them. DEL, SET and
        EXPIRE are refused everywhere.
        """
        client = _client(confirm_url)
        for command in (
            ("DEL", "postern:revoked:sessions"),
            ("SET", "postern:revoked:customer-at:cust", "1"),
            ("EXPIRE", "postern:revoked:sessions", "1"),
            ("SADD", "postern:revoked:clients", "vendor"),
            ("SREM", "postern:revoked:clients", "vendor"),
            ("SADD", "postern:revoked:customer-clients", "pair"),
            ("SREM", "postern:revoked:customer-clients", "pair"),
            ("ZADD", "postern:revoked:other", "1", "x"),
        ):
            with pytest.raises(redis.exceptions.NoPermissionError):
                await client.execute_command(*command)
        await client.aclose()

    async def test_confirm_cannot_run_destructive_or_administrative_commands(
        self, confirm_url: str
    ) -> None:
        client = _client(confirm_url)
        for command in (
            ("FLUSHALL",),
            ("FLUSHDB",),
            ("KEYS", "*"),
            ("SCAN", "0"),
            ("CONFIG", "SET", "maxmemory-policy", "allkeys-lru"),
            ("ACL", "LIST"),
            ("SHUTDOWN", "NOSAVE"),
        ):
            with pytest.raises(redis.exceptions.NoPermissionError):
                await client.execute_command(*command)
        await client.aclose()


class TestHealthUser:
    async def test_it_can_ping_and_nothing_else(self, acl_redis: tuple[str, int]) -> None:
        client = _connect(_url(acl_redis, ("postern_health", "postern-health-dev")))
        assert await client.ping() is True
        with pytest.raises(redis.exceptions.NoPermissionError):
            await client.execute_command("GET", "postern:revoked:sessions")
        await client.aclose()

"""The compose stack's Redis and Vault hardening, read off ``docker-compose.yml``.

``CLAUDE.md`` operator checklist item 6 tells a deployment to run Redis behind
``rediss://``, AUTH with a per-service ACL user and no public exposure, and to
enable a Vault audit device. The local stack used to have none of the four and
said so. These tests parse the compose file and ``dev-redis/users.acl`` as data, so
the stack cannot drift back without ``make ci`` noticing. They start nothing:
``tests/test_redis_acl_users.py`` is the one that runs Redis against the ACL
file, and the live bring-up is recorded in the commit that added this file.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
COMPOSE = yaml.safe_load((ROOT / "docker-compose.yml").read_text())
ACL = (ROOT / "dev-redis" / "users.acl").read_text()

SERVICES: dict[str, Any] = COMPOSE["services"]


def _command_text(service: str) -> str:
    command = SERVICES[service]["command"]
    return command if isinstance(command, str) else " ".join(command)


def _acl_users() -> dict[str, list[str]]:
    """``user <name> <tokens...>`` lines, comments dropped."""
    users: dict[str, list[str]] = {}
    for raw in ACL.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        assert parts[0] == "user", f"unexpected ACL line: {line!r}"
        users[parts[1]] = parts[2:]
    return users


class TestRedisIsNotPublished:
    def test_no_ports_mapping(self) -> None:
        assert "ports" not in SERVICES["redis"]

    def test_no_expose_of_a_plaintext_port(self) -> None:
        assert "expose" not in SERVICES["redis"]


class TestRedisIsTlsOnly:
    def test_plaintext_listener_is_off_and_tls_listener_is_on(self) -> None:
        command = _command_text("redis")
        assert "--port 0" in command
        assert "--tls-port 6379" in command

    def test_server_key_is_not_in_the_volume_the_services_mount(self) -> None:
        """Services get the CA certificate and never the server's private key."""
        for service in ("api", "confirm"):
            mounts = [m for m in SERVICES[service]["volumes"] if isinstance(m, str)]
            assert any(m.startswith("redis-ca:") for m in mounts), service
            assert not any(m.startswith("redis-tls:") for m in mounts), service

    def test_certificates_are_generated_not_committed(self) -> None:
        tracked = [p.name for p in ROOT.glob("dev-redis/*") if p.suffix in {".key", ".crt", ".pem"}]
        assert tracked == []
        assert "redis-certs" in SERVICES
        assert SERVICES["redis"]["depends_on"]["redis-certs"]["condition"] == (
            "service_completed_successfully"
        )


class TestServicesUseRedissWithTheirOwnUser:
    @pytest.mark.parametrize(
        ("service", "user"), [("api", "postern_api"), ("confirm", "postern_confirm")]
    )
    def test_url_is_rediss_with_credentials_and_a_ca(self, service: str, user: str) -> None:
        url = SERVICES[service]["environment"]["POSTERN_REDIS_URL"]
        parts = urlsplit(url)
        assert parts.scheme == "rediss"
        assert parts.hostname == "redis"
        assert parts.username == user
        assert parts.password
        query = parse_qs(parts.query)
        assert query["ssl_ca_certs"] == ["/redis-ca/ca.crt"]
        assert query["ssl_check_hostname"] == ["true"]

    def test_the_two_services_hold_different_credentials(self) -> None:
        urls = {SERVICES[s]["environment"]["POSTERN_REDIS_URL"] for s in ("api", "confirm")}
        assert len(urls) == 2


class TestAclFile:
    def test_default_user_is_disabled(self) -> None:
        assert _acl_users()["default"] == ["off"]

    def test_redis_loads_the_acl_file_from_a_read_only_mount(self) -> None:
        assert "--aclfile /etc/redis/users.acl" in _command_text("redis")
        mounts = SERVICES["redis"]["volumes"]
        assert "./dev-redis/users.acl:/etc/redis/users.acl:ro" in mounts

    def test_compose_credentials_match_the_acl_file(self) -> None:
        users = _acl_users()
        for service in ("api", "confirm"):
            parts = urlsplit(SERVICES[service]["environment"]["POSTERN_REDIS_URL"])
            assert parts.username in users
            assert f">{parts.password}" in users[parts.username]

    @pytest.mark.parametrize(
        "user", ["postern_health", "postern_api", "postern_confirm", "postern_operator"]
    )
    def test_no_user_holds_a_broad_grant(self, user: str) -> None:
        tokens = _acl_users()[user]
        assert "nopass" not in tokens
        assert "on" in tokens
        forbidden = {"+@all", "allcommands", "allkeys", "~*", "+@write", "+@dangerous", "+@admin"}
        assert not forbidden & set(tokens)
        # Selector groups are space-separated tokens too: check their contents.
        body = " ".join(tokens)
        for bad in ("+@all", "~*", "+@dangerous", "+@admin", "+keys", "+flushall", "+acl"):
            assert bad not in body

    def test_operator_holds_only_the_revocation_keys(self) -> None:
        tokens = _acl_users()["postern_operator"]
        patterns = [t for t in tokens if t.startswith(("~", "%", "&", "("))]
        assert patterns == ["~postern:revoked:*"]
        commands = {t for t in tokens if t.startswith("+")}
        assert not {"+flushall", "+flushdb", "+keys", "+scan", "+config|set", "+acl", "+del"} & (
            commands
        )
        assert not any(t.startswith("+@") for t in tokens)
        assert "-@all" in tokens
        assert "+eval" in commands
        assert "+get" not in commands  # no CLI verb issues a plain GET

    def test_operator_is_a_profiled_one_shot_on_the_api_image_not_a_service_user(self) -> None:
        revoke = SERVICES["revoke"]
        assert revoke["profiles"] == ["operator"]
        assert revoke["build"]["target"] == "api"
        assert "ports" not in revoke
        assert "redis-ca:/redis-ca:ro" in revoke["volumes"]
        assert not any("redis-tls" in m for m in revoke["volumes"])
        parts = urlsplit(revoke["environment"]["POSTERN_REDIS_URL"])
        assert parts.scheme == "rediss"
        assert parts.hostname == "redis"
        assert parts.username == "postern_operator"
        assert f">{parts.password}" in _acl_users()["postern_operator"]
        for service in ("api", "confirm"):
            assert "postern_operator" not in str(SERVICES[service]["environment"])
            assert "revoke" not in SERVICES[service].get("depends_on", {})

    def test_api_cannot_write_the_revocation_list(self) -> None:
        body = " ".join(_acl_users()["postern_api"])
        assert "(%R~postern:revoked:*" in body

    def test_redis_healthcheck_uses_the_ping_only_user(self) -> None:
        test = " ".join(SERVICES["redis"]["healthcheck"]["test"])
        assert "--tls" in test
        assert "--user postern_health" in test
        assert _acl_users()["postern_health"][-1] == "+ping"


class TestVaultAuditDevice:
    """The device is enabled by ``vault-init`` but the FILE lives in ``vault``.

    ``file_path`` is opened by the Vault server, so the volume that holds the
    log is mounted on ``vault`` and not on the one-shot that enables the device.
    ``/vault/logs`` is the directory the image's entrypoint chowns to the
    ``vault`` user, which is why the log goes there.
    """

    def test_vault_init_enables_a_file_audit_device(self) -> None:
        command = _command_text("vault-init")
        assert "vault audit enable file" in command
        assert "file_path=/vault/logs/audit.log" in command

    def test_a_failed_enable_fails_vault_init(self) -> None:
        """Only "already enabled" is tolerated, and the device must be listed."""
        # YAML folds the block into one line, so split it into statements.
        statements = [st.strip() for st in _command_text("vault-init").split(";")]
        enable = [st for st in statements if "vault audit enable" in st]
        assert len(enable) == 1
        assert "|| true" not in enable[0]
        assert enable[0].startswith('vault audit list | grep -q "^file/" ||')
        assert 'vault audit list | grep -q "^file/"' in statements

    def test_vault_init_is_safe_to_run_twice(self) -> None:
        """Every enable and create is guarded by an existence check, never `|| true`.

        A second run against a live Vault answered ``path is already in use``
        for transit. Only the already-exists condition may be tolerated, and it
        is tolerated by looking first, so any other failure still fails the
        service.
        """
        command = _command_text("vault-init")
        assert "|| true" not in command
        statements = [st.strip() for st in command.split(";")]
        guarded = {
            "vault secrets enable transit": 'vault secrets list | grep -q "^transit/" ||',
            "vault audit enable": 'vault audit list | grep -q "^file/" ||',
            "vault write -f transit/keys/": "vault read transit/keys/",
        }
        for action, guard in guarded.items():
            hits = [st for st in statements if action in st]
            assert len(hits) == 1, action
            assert guard in hits[0], action
            assert hits[0].index(guard) < hits[0].index(action), action
        # Policies are written with `vault policy write`, an upsert by design.
        assert command.count("vault policy write") == 2
        # A token is minted only when the one on the volume is not live for its policy.
        assert command.count("vault token create") == 1
        assert "vault token lookup" in command
        assert "exportable=true" not in command

    def test_vault_init_verifies_every_key_it_did_not_create(self) -> None:
        """An existing key is checked, not trusted: exportable or wrong type fails the service.

        Creating a key only when it is missing means a key somebody made
        exportable (or with another type) passes silently and `transit/export`
        then returns its private half. The loop reads both attributes back for
        every key, created now or earlier, and exits non-zero on a mismatch.
        """
        command = _command_text("vault-init")
        assert '"$$(vault read -field=exportable transit/keys/$$key)" != "false"' in command
        assert '"$$(vault read -field=type transit/keys/$$key)" != "rsa-2048"' in command
        loop = command[command.index("for key in") : command.index("done;")]
        assert "exit 1" in loop
        assert loop.index("vault write -f") < loop.index("-field=exportable")

    def test_a_reused_token_is_matched_exactly_and_renewed(self) -> None:
        command = _command_text("vault-init")
        assert 'grep -q "postern-$$role"' not in command
        assert '= "[default postern-$$1]"' in command
        assert "vault token renew" in command

    def test_vault_writes_the_log_to_a_named_volume(self) -> None:
        mounts = [m for m in SERVICES["vault"]["volumes"] if isinstance(m, str)]
        assert "vault-audit:/vault/logs" in mounts

    def test_the_volumes_are_declared(self) -> None:
        for volume in ("vault-audit", "redis-ca", "redis-tls"):
            assert volume in COMPOSE["volumes"]

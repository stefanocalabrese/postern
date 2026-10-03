"""``docker-compose.yml``'s ``vault-init`` script, run for real against a dev-mode Vault.

The script text is taken from the compose file (parsed as YAML, `$$` unescaped
the way compose does) and executed with ``docker exec`` inside a throwaway
``hashicorp/vault`` container started with testcontainers, with the same
environment variables the service sets. What this pins that the static checks in
``tests/test_compose_redis_hardening.py`` cannot: that a second run exits 0 and
changes nothing, and that an existing key which is exportable (or the wrong
type) fails the service instead of passing because it exists.
"""

from __future__ import annotations

import shlex
from collections.abc import Iterator
from pathlib import Path

import docker
import pytest
import yaml
from docker.errors import DockerException
from testcontainers.community.vault import VaultContainer

ROOT = Path(__file__).resolve().parent.parent
COMPOSE = yaml.safe_load((ROOT / "docker-compose.yml").read_text())
INIT = COMPOSE["services"]["vault-init"]
TOKEN = "init-test-root"  # noqa: S105
KEYS = ("postern-read", "postern-write", "postern-session")


def _script() -> list[str]:
    command = shlex.split(INIT["command"])
    assert command[:2] == ["sh", "-ec"]
    return [*command[:2], command[2].replace("$$", "$")]


class Stack:
    def __init__(self, container: VaultContainer) -> None:
        self._c = container.get_wrapped_container()

    def sh(self, *argv: str) -> tuple[int, str]:
        result = self._c.exec_run(
            list(argv),
            user="root",
            environment={"VAULT_ADDR": "http://127.0.0.1:8200", "VAULT_TOKEN": TOKEN},
            demux=False,
        )
        output = result.output
        assert isinstance(output, bytes)
        assert result.exit_code is not None
        return result.exit_code, output.decode()

    def init(self) -> tuple[int, str]:
        return self.sh(*_script())

    def snapshot(self) -> dict[str, str]:
        out: dict[str, str] = {}
        for role in ("read", "write"):
            out[f"token-{role}"] = self.sh("cat", f"/vault-tokens/{role}.token")[1]
        for key in KEYS:
            out[f"version-{key}"] = self.sh(
                "vault", "read", "-field=latest_version", f"transit/keys/{key}"
            )[1]
            out[f"exportable-{key}"] = self.sh(
                "vault", "read", "-field=exportable", f"transit/keys/{key}"
            )[1]
        return out


@pytest.fixture
def stack() -> Iterator[Stack]:
    try:
        docker.from_env().ping()
    except DockerException as exc:
        pytest.skip(f"Docker is not reachable, skipping the vault-init tests: {exc}")
    assert INIT["image"] == "hashicorp/vault:1.20"
    with VaultContainer(INIT["image"], root_token=TOKEN) as container:
        s = Stack(container)
        assert s.sh("mkdir", "-p", "/vault-tokens")[0] == 0
        yield s


def test_a_second_run_exits_zero_and_changes_nothing(stack: Stack) -> None:
    code, out = stack.init()
    assert code == 0, out
    first = stack.snapshot()
    assert all(first[f"exportable-{k}"].strip() == "false" for k in KEYS)
    code, out = stack.init()
    assert code == 0, out
    assert "reusing and renewing the read token" in out
    assert "reusing and renewing the write token" in out
    assert stack.snapshot() == first


def test_an_unusable_token_on_the_volume_is_replaced(stack: Stack) -> None:
    assert stack.init()[0] == 0
    before = stack.snapshot()
    assert stack.sh("sh", "-c", "echo not-a-token > /vault-tokens/read.token")[0] == 0
    code, out = stack.init()
    assert code == 0, out
    after = stack.snapshot()
    assert after["token-read"] != "not-a-token\n"
    assert after["token-read"] != before["token-read"]
    assert after["token-write"] == before["token-write"]


def test_a_token_with_both_policies_is_not_reused_for_either_role(stack: Stack) -> None:
    assert stack.init()[0] == 0
    before = stack.snapshot()
    code, both = stack.sh(
        "vault",
        "token",
        "create",
        "-policy=postern-read",
        "-policy=postern-write",
        "-period=24h",
        "-field=token",
    )
    assert code == 0, both
    assert stack.sh("sh", "-c", f"printf %s {both.strip()} > /vault-tokens/read.token")[0] == 0
    code, out = stack.init()
    assert code == 0, out
    after = stack.snapshot()
    assert after["token-read"] != both.strip()
    assert after["token-read"] != before["token-read"]


def test_an_existing_exportable_key_fails_the_service(stack: Stack) -> None:
    assert stack.sh("vault", "secrets", "enable", "transit")[0] == 0
    code, out = stack.sh(
        "vault", "write", "-f", "transit/keys/postern-session", "type=rsa-2048", "exportable=true"
    )
    assert code == 0, out
    code, out = stack.init()
    assert code != 0
    assert "postern-session" in out
    assert "exportable or not rsa-2048" in out
    # The init stopped before minting any token.
    assert stack.sh("test", "-e", "/vault-tokens/read.token")[0] != 0


def test_an_existing_key_of_another_type_fails_the_service(stack: Stack) -> None:
    assert stack.sh("vault", "secrets", "enable", "transit")[0] == 0
    code, out = stack.sh("vault", "write", "-f", "transit/keys/postern-read", "type=ed25519")
    assert code == 0, out
    code, out = stack.init()
    assert code != 0
    assert "postern-read" in out

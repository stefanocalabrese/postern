"""Runtime configuration for the API service (Task 4)."""

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    backend_base_url: str
    customer_jwks_uri: str | None = None
    customer_token_issuer: str | None = None
    audience: str = "postern"
    strict_headers: bool = False
    cache_ttl_seconds: int = 60
    # Task 12: the façade's `BackendClient(timeout=...)` applies a bare float
    # independently to each of connect/read/write/pool (Task 6 measured this
    # against httpx2 2.12.0), so a single "10 seconds" was really a worst
    # case of 40. These four defaults sum to the 10-second budget the old
    # single value was clearly meant to express, split by phase for a
    # same-VPC/PrivateLink backend: connect and pool-acquisition should be
    # sub-second in practice (2.0s/1.0s leave slack for jitter, not genuine
    # expected latency); write and read carry the actual request/response
    # bodies, and read gets the largest share (5.0s) because a transaction
    # export is the largest realistic response this server proxies.
    backend_connect_timeout_seconds: float = 2.0
    backend_write_timeout_seconds: float = 2.0
    backend_read_timeout_seconds: float = 5.0
    backend_pool_timeout_seconds: float = 1.0
    # Task 12: `HeaderBodyValidation.max_body_bytes` is opt-in and unset by
    # default (Task 5) because nothing in that task's scope could pick a
    # number on a deployment's behalf. This deployment's tool surface is
    # read-only JSON-RPC (a tool name plus small filter arguments: refs,
    # date ranges) with no file uploads and no bulk-write payloads, so 1 MiB
    # is generous headroom over any legitimate request while still bounding
    # the in-memory buffer `_drain` builds before this middleware's checks
    # run. A deployment that later adds a tool with a genuinely larger
    # request body (a bulk import, say) must raise this deliberately, not
    # rely on the default silently being big enough.
    max_body_bytes: int = 1_048_576
    # Task 12 adversarial pass: `StubTokenMinter` mints a fake bearer token
    # no real backend accepts ("Never deploy this", client.py). The
    # Vault-backed `InternalTokenMinter` meant to replace it does not exist
    # in this codebase yet, so `create_app` refuses to start with the stub
    # against a production-shaped configuration (real customer JWT auth
    # configured) by default -- fail closed, matching this codebase's
    # existing posture elsewhere. This flag is the explicit, named escape
    # hatch for a deliberate early rollout (real customer auth already live,
    # backend still a controlled sandbox) that must not be mistaken for
    # silence: grep for it before any milestone that touches real customer
    # money, and delete both the flag and the check it controls the day the
    # real minter exists.
    allow_stub_token_minter: bool = False

    @classmethod
    def from_env(cls) -> "Settings":
        """`os.environ["POSTERN_BACKEND_BASE_URL"]` has no safe default, so a
        missing value fails at startup with a `KeyError` naming it, rather
        than at the first customer request.

        `POSTERN_JWKS_URI` and `POSTERN_TOKEN_ISSUER` are optional (Task 13
        finding): `services/api/server.py::build_server` and
        `services/api/main.py::_refuse_stub_minter_in_production` both branch
        on `customer_jwks_uri is None` / `customer_token_issuer is None` to
        reach the documented no-auth path that `Settings.for_testing()` and
        the local docker-compose stack rely on
        (`test_build_server_stays_unauthenticated_when_neither_is_set`'s own
        docstring says so) -- but `os.environ[...]` can never produce `None`,
        only a `KeyError` or a `str`, even an empty one. Reading these two
        with a required `os.environ[...]` therefore made that no-auth path
        unreachable through `from_env()` at all: unset raised `KeyError`
        before startup got anywhere, and setting either to `""` (the compose
        convention for "off") produced a non-`None` string, which
        `build_server` treats as configured and `_refuse_stub_minter_in_production`
        treats as "production-shaped", refusing to start with `StubTokenMinter`.
        `os.environ.get(...) or None` collapses both "absent" and `""` to
        `None`, matching what the rest of the codebase already assumes this
        method can produce.
        """
        return cls(
            backend_base_url=os.environ["POSTERN_BACKEND_BASE_URL"],
            customer_jwks_uri=os.environ.get("POSTERN_JWKS_URI") or None,
            customer_token_issuer=os.environ.get("POSTERN_TOKEN_ISSUER") or None,
            audience=os.environ.get("POSTERN_AUDIENCE", "postern"),
            strict_headers=os.environ.get("POSTERN_STRICT_HEADERS") == "1",
            cache_ttl_seconds=int(os.environ.get("POSTERN_CACHE_TTL_SECONDS", "60")),
            backend_connect_timeout_seconds=float(
                os.environ.get("POSTERN_BACKEND_CONNECT_TIMEOUT_SECONDS", "2.0")
            ),
            backend_write_timeout_seconds=float(
                os.environ.get("POSTERN_BACKEND_WRITE_TIMEOUT_SECONDS", "2.0")
            ),
            backend_read_timeout_seconds=float(
                os.environ.get("POSTERN_BACKEND_READ_TIMEOUT_SECONDS", "5.0")
            ),
            backend_pool_timeout_seconds=float(
                os.environ.get("POSTERN_BACKEND_POOL_TIMEOUT_SECONDS", "1.0")
            ),
            max_body_bytes=int(os.environ.get("POSTERN_MAX_BODY_BYTES", str(1_048_576))),
            allow_stub_token_minter=os.environ.get("POSTERN_ALLOW_STUB_TOKEN_MINTER") == "1",
        )

    @classmethod
    def for_testing(cls) -> "Settings":
        return cls(backend_base_url="https://backend.test")

"""Runtime configuration for the API service (Task 4)."""

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    backend_base_url: str
    database_url: str = "postgresql+asyncpg://postern:postern@localhost:5432/postern"
    # Plan 3 Task 2: the key this process signs internal tokens with. A path
    # left unset means `create_app` generates an RSA key in process, which is
    # what `Settings.for_testing()` and the local docker-compose stack want:
    # nothing verifies these tokens locally, and a generated key needs no
    # secret material on disk. A real deployment sets the path to the PEM a
    # Vault Agent sidecar renders, and `FileKeySource` refuses a public key
    # at startup rather than at the first mint. `read_key_kid` must match the
    # `kid` the JWKS publishes, since a verifier selects the key by it.
    read_key_pem_path: str | None = None
    read_key_kid: str = "read-1"
    # S105 fires on the name containing "token", not on the value: this is
    # the `iss` claim every read token carries, a URL a verifier compares
    # against, and it is published in the JWKS discovery path.
    read_token_issuer: str = "https://mcp-read.bank.internal"  # noqa: S105
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

    @classmethod
    def from_env(cls) -> "Settings":
        """`os.environ["POSTERN_BACKEND_BASE_URL"]` has no safe default, so a
        missing value fails at startup with a `KeyError` naming it, rather
        than at the first customer request.

        `POSTERN_JWKS_URI` and `POSTERN_TOKEN_ISSUER` are optional (Task 13
        finding): `services/api/server.py::build_server` branches on
        `customer_jwks_uri is None` / `customer_token_issuer is None` to
        reach the documented no-auth path that `Settings.for_testing()` and
        the local docker-compose stack rely on
        (`test_build_server_stays_unauthenticated_when_neither_is_set`'s own
        docstring says so) -- but `os.environ[...]` can never produce `None`,
        only a `KeyError` or a `str`, even an empty one. Reading these two
        with a required `os.environ[...]` therefore made that no-auth path
        unreachable through `from_env()` at all: unset raised `KeyError`
        before startup got anywhere, and setting either to `""` (the compose
        convention for "off") produced a non-`None` string, which
        `build_server` treats as configured, building a `JWTVerifier` over
        two empty strings. `os.environ.get(...) or None` collapses both
        "absent" and `""` to `None`, matching what the rest of the codebase
        already assumes this method can produce.
        """
        return cls(
            backend_base_url=os.environ["POSTERN_BACKEND_BASE_URL"],
            database_url=os.environ.get(
                "POSTERN_DATABASE_URL",
                "postgresql+asyncpg://postern:postern@localhost:5432/postern",
            ),
            # `or None` for the same reason the two customer-auth variables
            # below carry it (Task 13 finding): an empty string is the compose
            # convention for "off", and `os.environ.get(...)` alone would hand
            # `FileKeySource` a `Path("")` to read a key from.
            read_key_pem_path=os.environ.get("POSTERN_READ_KEY_PEM_PATH") or None,
            read_key_kid=os.environ.get("POSTERN_READ_KEY_KID", "read-1"),
            read_token_issuer=os.environ.get(
                "POSTERN_READ_TOKEN_ISSUER", "https://mcp-read.bank.internal"
            ),
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
        )

    @classmethod
    def for_testing(cls) -> "Settings":
        return cls(backend_base_url="https://backend.test")

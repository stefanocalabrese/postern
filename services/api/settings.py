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
    read_token_issuer: str = "https://mcp-read.internal"  # noqa: S105
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
    # The same treatment for the consent/audit store, which had none of it:
    # `create_async_engine` carried no `connect_args`, so connecting fell
    # back to asyncpg's `connect(timeout=60)` default and a statement that
    # stalled after the connection was up had no deadline whatsoever. These
    # three reach `Database.__init__` at `services/api/main.py`, which
    # documents what each one bounds and what the command timeout costs; the
    # values are smaller than the backend's because everything this engine
    # runs is one indexed SELECT on the consents table or one audit INSERT,
    # not a transaction export. Worst case per database operation: 1.0 +
    # 2.0 + 3.0 = 6.0s.
    database_connect_timeout_seconds: float = 2.0
    database_command_timeout_seconds: float = 3.0
    database_pool_timeout_seconds: float = 1.0
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
    # A wall-clock bound on the whole HTTP request, enforced by
    # `services/api/asgi/request_deadline.py`. Every other number in this
    # file bounds ONE wait on a socket that eventually says something; this
    # one exists because a path silent in both directions produces no such
    # event, and `docs/verification/2026-09-17-query-stall-deadline.md`
    # measured a request against one as not returned at its 60-second cap, on
    # two separate paths. That is a cap, not a bound: whether either request
    # ever returns was not determined.
    #
    # 101.0 is derived, not chosen, and every term is a number already in this
    # repository. Per DATABASE OPERATION, from `Database.__init__`'s own
    # arithmetic (`postern_core/store/engine.py`): 1.0 pool + 2.0 connect +
    # 3.0 statement = 6.0s when the checkout opens a connection, and 1.0 +
    # 3x3.0 + 3.0 = 13.0s on a recycled one, where `pool_pre_ping=True` makes
    # the check three statements (BEGIN, the ping, ROLLBACK) that each inherit
    # `command_timeout`. Per BACKEND REQUEST, from the four fields above:
    # 1.0 pool + 2.0 connect + 2.0 write + 5.0 read = 10.0s. Operations per
    # `tools/call`: TWO audit writes since 2026-09-18 (an entry row committed
    # before the backend is reached and a completion row after the tool
    # finishes -- `services/api/middleware/audit.py`), and the consent lookup
    # is one when it succeeds -- `services/api/consent.py` caches a successful
    # answer on `request.state` -- but a lookup that RAISES is never cached,
    # and that module measures FIVE evaluations for one `tools/call` carrying
    # arguments. They run in that order, since consent is evaluated inside
    # `_get_tool` and the entry row is written from the façade below it. The
    # ceiling is therefore the arrangement where the first four evaluations
    # burn 13.0s each and the fifth still succeeds:
    # 5x13.0 + 13.0 + 10.0 + 13.0 = 101.0s.
    #
    # WHAT THAT SUM BOUNDS is a reachable store and a reachable backend,
    # which is the qualifier `postern_core/store/engine.py` already carries
    # for its own numbers. Every term above is a deadline on a wait that ends
    # in an answer, a reset or a refusal. Against a path silent in BOTH
    # directions none of them bounds anything -- `command_timeout` fires and
    # SQLAlchemy's invalidation then awaits asyncpg's undeadlined close
    # (`docs/verification/2026-09-17-query-stall-deadline.md`, not returned at
    # a 60-second cap) -- and the entry write adds one more database operation
    # that can meet exactly that condition. On such a path this value is the
    # cap this middleware imposes, not a bound the terms predict.
    #
    # That number is uncomfortably large and is written here rather than
    # quietly rounded down. It is longer than any consumer AI client will
    # wait, so in practice the client gives up first; what this deadline
    # returns is the WORKER, not a timely answer. Two more honest readings of
    # it: the realistic success ceiling is 13.0 + 13.0 + 10.0 + 13.0 = 49.0s
    # and the realistic denial ceiling (every lookup raising, the backend
    # never reached) is 5x13.0 + 13.0 = 78.0s -- unchanged by the entry
    # write, because a refused call never reaches the backend and so never
    # writes one -- while a healthy call was measured at 0.10s end to end in
    # the verification record above. And the reason to sit AT the ceiling
    # rather than below it is a property, not caution: a deadline above every
    # individually-bounded sum can only fire once some wait has already
    # escaped its own deadline, which keeps this from preempting requests the
    # store and the backend would still have served -- and, because a
    # cancelled request loses whichever audit row it was writing
    # (`request_deadline.py`, and `docs/decisions/0006-audit-write-failure.md`),
    # every second shaved off this value buys back latency by trading away
    # audit rows for calls that were merely slow.
    #
    # Lowering it honestly means lowering the terms it is built from, which is
    # a change to the store and backend budgets above, not to this line.
    #
    # Zero and negative are REFUSED by `RequestDeadline.__init__`, so a
    # `POSTERN_REQUEST_DEADLINE_SECONDS=0` reached for as an off switch fails
    # at startup instead of 504-ing every request. There is no off switch;
    # raise the number instead.
    request_deadline_seconds: float = 101.0

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
                "POSTERN_READ_TOKEN_ISSUER", "https://mcp-read.internal"
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
            database_connect_timeout_seconds=float(
                os.environ.get("POSTERN_DATABASE_CONNECT_TIMEOUT_SECONDS", "2.0")
            ),
            database_command_timeout_seconds=float(
                os.environ.get("POSTERN_DATABASE_COMMAND_TIMEOUT_SECONDS", "3.0")
            ),
            database_pool_timeout_seconds=float(
                os.environ.get("POSTERN_DATABASE_POOL_TIMEOUT_SECONDS", "1.0")
            ),
            max_body_bytes=int(os.environ.get("POSTERN_MAX_BODY_BYTES", str(1_048_576))),
            request_deadline_seconds=float(
                os.environ.get("POSTERN_REQUEST_DEADLINE_SECONDS", "101.0")
            ),
        )

    @classmethod
    def for_testing(cls) -> "Settings":
        return cls(backend_base_url="https://backend.test")

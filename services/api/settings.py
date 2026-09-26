"""Runtime configuration for the API service (Task 4).

Every numeric field below is read through `postern_core/config.py`'s
`int_from_env` or `float_from_env` rather than a bare ``int()`` / ``float()``,
which does three things and no more: an empty string means unset, a value
outside the stated bound raises with the VARIABLE's name in the message, and
the reason travels with the refusal. That module carries why the refusal
belongs at parse time rather than at first use; the bounds themselves are
stated one per call below, because each has a different reason.

THE ONE ASYMMETRY WORTH READING BEFORE THE CALLS. Three of the four backend
phases and two of the three database ones refuse zero; both POOL timeouts
accept it. Measured on 2026-09-25, against a real socket and a real Postgres:
``connect``/``read``/``write`` at zero make httpx2 2.12.0 fail EVERY request
(``ConnectTimeout``, ``ReadTimeout``, ``WriteTimeout``) against a server that
answers in a millisecond, and a pool timeout at zero serves the same request
200 -- because a pool timeout bounds a wait for a free connection, and on an
unsaturated pool there is no wait to bound. Under saturation (one connection,
two concurrent requests, a 0.3s handler) ``pool=1.0`` answered both 200 while
``pool=0.0`` answered the second ``PoolTimeout`` immediately. That is a
coherent thing for an operator to want -- shed load rather than queue -- so
zero stays legal there and only negatives are refused. It is the distinction
`services/confirm/settings.py`'s `MIN_DEVICE_CODE_TTL_SECONDS` insists on: a
bound refuses what is UNREPRESENTABLE, not what is unwise.
"""

import os
from dataclasses import dataclass

from postern_core.config import float_from_env, int_from_env


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
    # ZT-5: how many proxies in front of this process append to
    # `X-Forwarded-For`. `services/api/middleware/risk.py`'s `_client_ip`
    # reads the n-th entry from the RIGHT, which is the address the outermost
    # proxy this deployment trusts wrote; the leftmost entry is the one the
    # caller writes, and reading it let an attacker pin or rotate their
    # apparent address at will against the IP-anomaly control that decision
    # record 0010 makes the primary compensating control for a replayed token.
    #
    # ZERO, deliberately, and it is the value that trusts the header for
    # NOTHING: the socket peer is used instead. A deployment behind an ALB or
    # the Istio gateway MUST raise this to the number of hops that actually
    # append, or every call is attributed to the proxy and the diversity and
    # impossible-travel checks see one unchanging address. The opposite
    # default would have a deployment with no proxy trusting a header its
    # caller controls, which is the defect, so the number that is wrong in
    # the safe direction is the default and the deployment states its own
    # topology.
    trusted_proxy_hops: int = 0
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
    # THE CEILING, and it is a deployment-wide number wearing a per-service
    # name. At most `pool_size + max_overflow` connections from this replica
    # at once; multiply by replicas, add what `services/confirm` holds against
    # the same database, and the total has to clear `max_connections`.
    # `postern_core.store.engine`'s `Database` carries that arithmetic and
    # `dev-docs/decisions/0013-connection-pool-ceiling.md` carries the
    # derivation.
    #
    # 5 + 10 IS WHAT THIS SERVICE HAS BEEN RUNNING, inherited rather than
    # chosen: neither argument was passed until 2026-09-26 and SQLAlchemy's
    # own defaults are these two numbers. Keeping them makes this change a
    # configurability change and not a capacity change, which are two things
    # to find out about separately when a deployment starts refusing.
    #
    # What the ceiling buys is concurrent REQUESTS, not connections per
    # request: one `tools/call` costs two to seven checkouts (one to five
    # consent lookups, since a lookup that raises is never cached, plus an
    # entry and a completion audit row) and holds one at a time. Fifteen is
    # therefore fifteen tool calls simultaneously inside a database
    # operation, not fifteen tool calls in flight.
    database_pool_size: int = 5
    database_max_overflow: int = 10
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
    # (`request_deadline.py`, and `dev-docs/decisions/0006-audit-write-failure.md`),
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
            # NO CEILING here or on any number below, and the argument is the
            # one `services/confirm/settings.py`'s `_device_code_ttl` made for
            # the device-code lifetime: a value that is too LARGE is a risk an
            # operator can reason about and trade off, while a value that is
            # too SMALL does not weaken a control, it produces a process that
            # cannot serve a request at all. Only the second kind is refused.
            cache_ttl_seconds=int_from_env(
                "POSTERN_CACHE_TTL_SECONDS",
                60,
                minimum=1,
                because=(
                    "It is the seconds behind the `ttlMs` this server advertises on every "
                    "discovery result; FastMCP 4.0.3 refuses a cache_ttl at or below zero "
                    "when the server is built, and nothing here can express 'no hint'."
                ),
            ),
            trusted_proxy_hops=int_from_env(
                "POSTERN_TRUSTED_PROXY_HOPS",
                0,
                minimum=0,
                because=(
                    "It is how many proxies in front of this process append to "
                    "X-Forwarded-For; zero is the default and already means 'trust the "
                    "header for nothing', so there is nothing below it left to express."
                ),
            ),
            backend_connect_timeout_seconds=float_from_env(
                "POSTERN_BACKEND_CONNECT_TIMEOUT_SECONDS",
                2.0,
                minimum=0,
                exclusive=True,
                because=(
                    "It bounds the TCP connect and TLS handshake to the operator's "
                    "backend; at zero httpx2 answers every request ConnectTimeout, so the "
                    "server reaches no backend at all."
                ),
            ),
            backend_write_timeout_seconds=float_from_env(
                "POSTERN_BACKEND_WRITE_TIMEOUT_SECONDS",
                2.0,
                minimum=0,
                exclusive=True,
                because=(
                    "It bounds sending the request body to the backend; at zero httpx2 "
                    "answers every request WriteTimeout."
                ),
            ),
            backend_read_timeout_seconds=float_from_env(
                "POSTERN_BACKEND_READ_TIMEOUT_SECONDS",
                5.0,
                minimum=0,
                exclusive=True,
                because=(
                    "It bounds reading the backend's response; at zero httpx2 answers "
                    "every request ReadTimeout."
                ),
            ),
            # ZERO IS LEGAL HERE, unlike the three phases above. See the module
            # docstring for the measurement: a pool timeout bounds the wait for
            # a free connection, so zero means 'do not queue, shed the request',
            # which is a bulkhead an operator may genuinely want. A NEGATIVE
            # value behaves identically to zero and so cannot express the one
            # thing an operator would reach for it to mean.
            backend_pool_timeout_seconds=float_from_env(
                "POSTERN_BACKEND_POOL_TIMEOUT_SECONDS",
                1.0,
                minimum=0,
                because=(
                    "It bounds how long a request waits for a free pooled connection to "
                    "the backend; zero sheds instead of queueing, and a negative value "
                    "does the same thing while reading as 'wait forever'."
                ),
            ),
            database_connect_timeout_seconds=float_from_env(
                "POSTERN_DATABASE_CONNECT_TIMEOUT_SECONDS",
                2.0,
                minimum=0,
                exclusive=True,
                because=(
                    "It becomes asyncpg's connect(timeout=); at zero every connection to "
                    "a reachable Postgres raises TimeoutError, so no consent lookup and "
                    "no audit write can complete."
                ),
            ),
            database_command_timeout_seconds=float_from_env(
                "POSTERN_DATABASE_COMMAND_TIMEOUT_SECONDS",
                3.0,
                minimum=0,
                exclusive=True,
                because=(
                    "It becomes asyncpg's command_timeout, which asyncpg itself refuses "
                    "at or below zero -- but not until the first connect, with a message "
                    "naming the parameter and not this variable."
                ),
            ),
            database_pool_timeout_seconds=float_from_env(
                "POSTERN_DATABASE_POOL_TIMEOUT_SECONDS",
                1.0,
                minimum=0,
                because=(
                    "It becomes SQLAlchemy's pool_timeout; zero sheds instead of queueing "
                    "when the pool is saturated, and a negative value does the same thing "
                    "while reading as 'wait forever'."
                ),
            ),
            database_pool_size=int_from_env(
                "POSTERN_DATABASE_POOL_SIZE",
                5,
                minimum=1,
                because=(
                    "It becomes SQLAlchemy's pool_size, the connections this replica keeps "
                    "open, and replicas x (pool_size + max_overflow) has to clear the "
                    "database's max_connections. Zero is not a small pool but an unbounded "
                    "one: measured, an engine at pool_size=0 held 25 connections at once."
                ),
            ),
            database_max_overflow=int_from_env(
                "POSTERN_DATABASE_MAX_OVERFLOW",
                10,
                minimum=0,
                because=(
                    "It becomes SQLAlchemy's max_overflow, the connections this replica may "
                    "open above pool_size and close again on return. Zero is a legitimate "
                    "setting and means no burst; -1 is the off switch, and an engine set to "
                    "it held 25 connections at once against a ceiling that read as one."
                ),
            ),
            # A FLOOR OF ONE BYTE, stated as what it is rather than dressed up.
            # At zero `_drain` raises on any body at all, so every tools/call --
            # every request this server exists to serve -- is refused 413 while
            # GETs still pass, which is a service that looks up and answers
            # nothing. Above one byte nothing here can say what is enough: the
            # smallest JSON-RPC envelope measures 51 bytes, but the useful floor
            # is whatever the largest legitimate tool argument set costs, and
            # that is a property of the tool surface rather than of this line.
            max_body_bytes=int_from_env(
                "POSTERN_MAX_BODY_BYTES",
                1_048_576,
                minimum=1,
                because=(
                    "It is the ceiling on a request body this server will buffer; at zero "
                    "every request carrying a body is refused 413, which is every "
                    "tools/call."
                ),
            ),
            request_deadline_seconds=float_from_env(
                "POSTERN_REQUEST_DEADLINE_SECONDS",
                101.0,
                minimum=0,
                exclusive=True,
                because=(
                    "It is a wall-clock bound on the whole request; at zero every request "
                    "expires before the app runs a line, and there is deliberately no off "
                    "switch -- raise the number instead."
                ),
            ),
        )

    @classmethod
    def for_testing(cls) -> "Settings":
        return cls(backend_base_url="https://backend.test")

"""Composition root. uvicorn targets `services.api.main:app`.

Four questions earlier tasks deliberately deferred here ("Task 12 owns
composition"); the reasoning for each lives in
`dev-docs/decisions/0003-composition-root.md` and is summarised at its wiring
site below:

1. `BackendClient` lifecycle and `aclose()` on shutdown, joined by `Database`
   lifecycle (Task 6) -- `_close_resources_after_fastmcp_shutdown`.
2. The façade's real per-call timeout budget -- `_backend_timeout`.
3. `HeaderBodyValidation.max_body_bytes`, sourced from `Settings` -- wired
   into the `Middleware(...)` call below.
4. `strict_headers`, sourced from `Settings` -- wired into the same call.

Plan 3 Task 2 built the real minter here, replacing `StubTokenMinter` and
its fake bearer token no backend accepts. This process now holds one
`ReadTokenMinter` over an `InternalTokenMinter` carrying a READ key, and no
write key and no write scope: `READ_SCOPES` has no `payments.svc` entry, so
a write audience raises `KeyError` instead of minting.

`_refuse_stub_minter_in_production` and the `allow_stub_token_minter` flag
that disarmed it are deleted with this commit. That guard read a settings
shape (`customer_jwks_uri` and `customer_token_issuer` both set) and never
which minter `create_app` built, so once the stub stopped being constructed
here it refused exactly the deployments running the genuine minter.
Measured before removal against that settings shape: no flag raised
`RuntimeError` naming `StubTokenMinter`, and `POSTERN_ALLOW_STUB_TOKEN_MINTER=1`
started the app with a `ReadTokenMinter`. Between that deletion and 2026-09-18
nothing checked minter identity or deployment shape at startup, and the
ephemeral-key warning below restored none of it: that fires on a generated
signing key, which is a different hazard. What checks it now is
`postern_core.auth.minter_probe.refuse_unverifiable_minter`, called in
`create_app` below on the minter that function has just built: one probe
token, verified against the key set this same process publishes, and no start
if the two disagree. It reads no settings, so the shape the deleted guard
mistook for a deployment never enters into it, and it has no override flag.
`dev-docs/decisions/0003-composition-root.md` and `0004-base-images.md` each carry
dated amendments recording the deletion and what did and did not replace it.

Task 6 adds the database: one `Database` per process, built unconditionally
from `settings.database_url` (the constructor never connects --
`create_async_engine` is lazy), handed to `AuditMiddleware` so every tool
call is recorded regardless of whether real customer auth is configured, and
closed on shutdown alongside the backend client. Consent enforcement keeps
its own, narrower condition (`has_real_customer_auth`, unchanged from Task
4): `build_server` only receives a `db` to check consent against when there
is a validated token's subject to check it for, since consent has nowhere to
read a customer from otherwise.
"""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import httpx2
from fastmcp.server.auth import AuthProvider
from fastmcp.server.http import StarletteWithLifespan
from postern_core.auth.internal_jwt import _LIFETIME, InternalTokenMinter
from postern_core.auth.keys import (
    GeneratedKeySource,
    KeySource,
    choose_key_source,
)
from postern_core.auth.minter_probe import refuse_unverifiable_minter
from postern_core.auth.read_minter import JtiReplayCache, ReadTokenMinter
from postern_core.auth.revocation import create_revocation_store, decision_scope
from postern_core.config import bool_from_env, enforce_redis_requirement
from postern_core.env_inventory import enforce_known_environment
from postern_core.facade.client import BackendClient
from postern_core.identity import CustomerRef, CustomerResolver
from postern_core.store.engine import Database
from starlette.middleware import Middleware

from services.api.asgi.header_validation import HeaderBodyValidation
from services.api.asgi.request_deadline import RequestDeadline
from services.api.jwks import jwks_route
from services.api.middleware.audit import AuditMiddleware, record_data_touch
from services.api.middleware.revocation import RevocationMiddleware
from services.api.middleware.risk import RiskMiddleware
from services.api.server import build_server, token_customer_resolver
from services.api.settings import Settings

# Subject of the one token `create_app` mints to check its own minter. It is a
# reference to nobody: `CustomerRef` accepts it (the pattern is `cust[:_]`
# followed by alphanumerics) and no fixture, `stub/backend.py::OWNERS` entry
# or test in this repository uses it. The token it appears in is verified in
# process and discarded; nothing sends it anywhere.
_STARTUP_PROBE = CustomerRef(value="cust_startupprobe")


def _read_key_source(settings: Settings) -> KeySource:
    """The READ signing key: inside Vault, from a PEM, or generated here.

    THREE BRANCHES, ONE DECISION, AND IT IS NOT MADE HERE. The if/else this
    function used to be moved into
    `postern_core.auth.keys.choose_key_source` on 29 September 2026, because
    the same decision is made three times in this repository -- this key, the
    WRITE key in `services/confirm/minter.py`, and the device grant's READ key
    in `services/confirm/main.py` -- and `.importlinter` forbids the two
    services sharing anything directly. What is left here is the argument
    list, which is this process's half of the read/write split: a READ kid, a
    READ PEM variable, and the name of a READ transit key. There is no
    spelling of this call that names a write key.

    VAULT FIRST when ``POSTERN_VAULT_ADDR`` is set, and then the private key
    is not in this process at all: `postern_core.auth.vault` carries what that
    buys, what it costs per call, and why a Vault plus a PEM is refused rather
    than ordered.

    A set `read_key_pem_path` is the Vault Agent shape: the sidecar renders
    the private key to a file and this process reads it once at startup, so
    `FileKeySource`'s public-key rejection fires before uvicorn serves rather
    than at the first customer request. Neither set means generate 2048 bits
    in process, which `Settings.for_testing()` and the local docker-compose
    stack both want: nothing verifies these tokens locally (the backend stub
    reads `sub` out of the payload without checking the signature, by design),
    so a generated key needs no secret on disk and no key rotation.

    A process restart throws a generated key away, which is exactly why a
    deployment must set one of the other two: the JWKS Task 3 publishes would
    otherwise change under every verifier on every restart.
    `warn_ephemeral_signing_key` carries why that is neither gated nor fatal,
    and `docs/verification/2026-09-18-multi-replica-jwks.md` measures what the
    discarded key costs a caller.

    Production deployments MUST set ``POSTERN_REQUIRE_PEM_KEY=1`` to refuse
    startup with an ephemeral key. Without it, a restart changes the JWKS and
    every verifier rejects all tokens until they re-fetch.
    """
    source = choose_key_source(
        role="READ",
        kid=settings.read_key_kid,
        vault=settings.vault,
        vault_key_name=settings.vault_read_key_name,
        pem_path=settings.read_key_pem_path,
        pem_env_var="POSTERN_READ_KEY_PEM_PATH",
    )
    # Audit finding (2026-09-21): refuse to start with ephemeral key when
    # the operator has explicitly required a persisted PEM. Without this,
    # a restart changes the JWKS and every verifier rejects all tokens.
    #
    # KEYED ON THE OBJECT THAT WAS BUILT, not on `read_key_pem_path is None`
    # read a second time from settings. That is the lesson `d203606` left --
    # a control keyed on configuration shape drifts away from what the
    # process actually built -- and since 29 September 2026 it is also the
    # difference between right and wrong: a Vault-backed deployment sets no
    # PEM path, so the settings-shaped test would have refused to start the
    # one configuration in which there is no ephemeral key and no private key
    # in the process at all.
    #
    # READ THROUGH `bool_from_env` SINCE 2026-09-26, AND THAT CHANGED WHAT
    # SOME DEPLOYMENTS DO. It was `== "1"`, so `POSTERN_REQUIRE_PEM_KEY=true`
    # meant "do not require a PEM key" -- an operator who believed they had
    # banned in-process signing keys had banned nothing, and would find out
    # after a restart, from `BadSignatureError` against every token the
    # previous process minted. That error reads like forgery, not like a flag
    # that did nothing, which is why this one was worth converting rather
    # than documenting. `true`, `yes` and `on` now arm it; an unreadable
    # value refuses to start instead of defaulting to off.
    if isinstance(source, GeneratedKeySource) and bool_from_env(
        "POSTERN_REQUIRE_PEM_KEY",
        False,
        because=(
            "It refuses startup on an ephemeral signing key. Left off, a restart "
            "generates a new key, the published JWKS changes, and every token "
            "minted before it stops verifying."
        ),
    ):
        raise RuntimeError(
            "POSTERN_REQUIRE_PEM_KEY is set but this process generated an ephemeral "
            "signing key: neither POSTERN_READ_KEY_PEM_PATH nor POSTERN_VAULT_ADDR is "
            "set. A persisted key is required for production: a restart with an "
            "ephemeral key changes the JWKS and invalidates all existing tokens."
        )
    return source


def _backend_timeout(settings: Settings) -> httpx2.Timeout:
    """A bare `float` passed to `httpx2.AsyncClient(timeout=...)` applies
    independently to connect, read, write and pool (Task 6 measured this),
    so the constructor's old `timeout: float = 10.0` default was a worst
    case of up to 40 seconds, not 10. `Settings` now owns four phase
    budgets that a deployment can tune independently; see the field
    comments in `services/api/settings.py` for the reasoning behind the
    defaults.
    """
    return httpx2.Timeout(
        connect=settings.backend_connect_timeout_seconds,
        read=settings.backend_read_timeout_seconds,
        write=settings.backend_write_timeout_seconds,
        pool=settings.backend_pool_timeout_seconds,
    )


def _close_resources_after_fastmcp_shutdown(
    app: StarletteWithLifespan, backend: BackendClient, db: Database, key_source: KeySource
) -> None:
    """Wires `backend.aclose()`, (Task 6) `db.close()` and (2026-09-29)
    `key_source.close()` into the app's own ASGI lifespan.

    `FastMCP.http_app()` returns a `StarletteWithLifespan` whose lifespan
    starts and stops FastMCP's session manager (`fastmcp/server/http.py`).
    FastMCP's docs warn that nesting apps without passing that lifespan
    through leaves the session manager uninitialised, so this does not
    replace it: it reads the existing `app.router.lifespan_context`,
    wraps it, and writes the wrapped version back. FastMCP's startup and
    shutdown run completely unchanged inside the `async with`; the backend
    client and the database are closed only after that block exits, i.e.
    only after FastMCP's own shutdown has finished, so no in-flight request
    can observe either as closed. Proven in `tests/test_asgi_app.py`
    (`test_lifespan_runs_fastmcps_own_startup_then_closes_the_backend_client_after_its_shutdown`):
    a real tool call succeeds while the app is running (which requires
    FastMCP's own lifespan to have started the session manager), and both
    the backend and the database are confirmed closed exactly once, only
    after shutdown completes.
    """
    original_lifespan = app.router.lifespan_context

    @asynccontextmanager
    async def lifespan(app: StarletteWithLifespan) -> AsyncIterator[None]:
        async with original_lifespan(app):
            yield
        await backend.aclose()
        await db.close()
        # The third resource, and the only synchronous one: a Vault-backed
        # `KeySource` holds an `httpx2.Client` connection pool, and the two
        # local ones hold nothing and no-op. Called through the Protocol
        # rather than behind an `isinstance`, for the reason
        # `postern_core.auth.keys.KeySource.close` gives -- a composition root
        # that has to ask which implementation it built is the first thing to
        # break "nothing above the seam knows".
        #
        # LAST, after the backend client, because a token minted for an
        # in-flight request is useless once that request cannot be sent.
        key_source.close()

    app.router.lifespan_context = lifespan


def create_app(
    settings: Settings | None = None,
    *,
    resolver: CustomerResolver | None = None,
    transport: httpx2.AsyncBaseTransport | None = None,
    auth_override: AuthProvider | None = None,
) -> StarletteWithLifespan:
    """Assemble the read-path ASGI app.

    `resolver`, `transport` and `auth_override` are keyword-only test seams:
    production (the module-level `app` attribute below, built by
    `__getattr__`) always resolves the customer from the validated access
    token, always reaches the backend over the real network, and always
    builds its `JWTVerifier` from `Settings`. Tests inject a fixed customer,
    an `httpx2.MockTransport`, and (Task 4) a `JWTVerifier` built from a
    generated key pair so a consent-enforcement test can mint its own
    tokens, the same way every other task in this plan already mocks its
    external dependencies because there is no live customer token, real
    operator backend or real identity provider to call against in CI.
    """
    # FIRST, BEFORE ANY VALUE IS READ. `Settings.from_env` below validates the
    # value behind every name it asks for and cannot see a name nobody asks
    # for, so a misspelt variable reaches it as an unset one and takes a
    # default in silence. This refuses on the name instead, and it runs first
    # because when it fires its message explains the failures the guards below
    # would otherwise report: an operator who typed POSTERN_JWKS_UR is told
    # about the typo rather than about a service running in no-auth mode.
    # `postern_core/env_inventory.py` carries the three populations, why only
    # the third refuses, and why the escape hatch cannot be the hole.
    enforce_known_environment(service="api")
    settings = settings or Settings.from_env()

    # Plan 3 Task 2: one minter, built over the READ key only. `BackendClient`
    # calls a `TokenMinter` (`customer, audience -> str`); `ReadTokenMinter`
    # is the adapter onto `InternalTokenMinter.mint`, whose signature is
    # wider. `consent_id` and `client_id` from handoff §7.2 are not supplied
    # yet: `client_id` is reachable only from `get_access_token()`, which
    # `BackendClient.get_json` has no access to, and `consent_id` needs the
    # tool layer to pass the `consents` row id, so both are façade-signature
    # plumbing a later task owns rather than a value that could be guessed
    # here.
    read_key_source = _read_key_source(settings)
    # ZT-7: the shared revocation store, Redis-backed whenever
    # `POSTERN_REDIS_URL` is set and per-replica-and-forgotten-on-restart
    # otherwise. Until 2026-09-23 this line built a bare `RevocationList`,
    # kept it in a local, and gave nothing a way to write to it: no route, no
    # CLI, no persistence, and not even a handle on `app.state`. The operator
    # surface is `postern_core.auth.revoke_cli` and the check that enforces it
    # is `services/api/middleware/revocation.py`'s `RevocationMiddleware`,
    # installed below.
    revocation_store = create_revocation_store()
    # ZT-1 A10: the jti replay cache, checked after mint. Still in-memory and
    # per replica, which is a narrower claim than it looks -- it catches a
    # duplicate jti this process minted, within one token lifetime.
    jti_cache = JtiReplayCache(max_age_seconds=_LIFETIME.total_seconds())
    read_minter = ReadTokenMinter(
        InternalTokenMinter(issuer=settings.read_token_issuer, key_source=read_key_source),
        jti_cache=jti_cache,
    )

    # Before that minter reaches anything that could send one of its tokens:
    # mint one, and refuse to start unless it verifies against the key set
    # `jwks_route` below publishes from this same `read_key_source`. Keyed on
    # the object above having been BUILT, never on a settings shape, for the
    # reason `d203606` left in the module docstring.
    # `refuse_unverifiable_minter` carries the rest: why this one refuses
    # where `warn_ephemeral_signing_key` above only warns, why neither takes
    # an override flag, and why the write path has no equivalent call yet.
    #
    # HERE and not lower down, for a reason worth stating: `BackendClient`
    # opens an `httpx2.AsyncClient` and `Database` builds an engine, and both
    # are closed only by `_close_resources_after_fastmcp_shutdown`, which a
    # `RuntimeError` out of this function means never runs. Refusing before
    # either exists abandons no open resource.
    #
    # The `decision_scope(False)` is what lets this probe run at all. The
    # minter refuses when no revocation decision has been published for the
    # call, and at startup there is no request and therefore no middleware to
    # publish one -- that refusal is the point of the default (see
    # `postern_core.auth.revocation`'s `require_revocation_decision`), so the
    # one call that legitimately has no decision states so rather than
    # softening the default for every other caller. `_STARTUP_PROBE` is a
    # reference to nobody and the token is verified in process and discarded.
    # The scope is exited before this function returns, so nothing inherits
    # it: `decision_scope` resets the ContextVar through the token `set`
    # returned, and a value left set here would become the standing default
    # for every request task spawned from this context.
    def _probe_token() -> str:
        with decision_scope(False):
            return read_minter(_STARTUP_PROBE, "accounts.svc")

    refuse_unverifiable_minter(
        _probe_token,
        built=read_minter,
        key_source=read_key_source,
        role="READ",
    )
    backend = BackendClient(
        settings.backend_base_url,
        read_minter,
        transport=transport,
        timeout=_backend_timeout(settings),
        # The entry audit row, committed before this client reaches the
        # operator's backend and failing the call if it cannot be
        # (`services/api/middleware/audit.py`, and
        # `dev-docs/decisions/0006-audit-write-failure.md` for why closed rather
        # than open). Wired here because this is the only place that holds
        # both halves: the façade that will make the request, and the
        # middleware module that knows what to record about it.
        #
        # The hook is a module-level function, not a bound method, and that
        # is the shape the mismatch forces: this client is built once per
        # process while the row is per call, so `record_data_touch` reads the
        # per-call values off a `ContextVar` the middleware sets. Nothing
        # about a tool, an argument or a store crosses into
        # `postern_core.facade` -- it depends on a zero-argument callable
        # Protocol and nothing else.
        before_backend_request=record_data_touch,
    )
    # Task 6: one `Database` per process, built unconditionally.
    # `create_async_engine` is lazy (Task 1's own tests construct one against
    # an address that is never reached), so this never blocks startup and
    # never requires a reachable Postgres just to assemble the app -- only
    # the first actual query does. Built here, not gated the way `consent_db`
    # below is, because `AuditMiddleware` must record every call regardless
    # of whether real customer auth is configured: the local docker-compose
    # stack and `Settings.for_testing()` both still want an audit trail.
    #
    # The three timeouts are the store's equivalent of `_backend_timeout`
    # above, and they are passed as asyncpg `connect_args` rather than in the
    # URL, which silently hands the driver a string it cannot add to a float.
    # They bound the connect, every statement, and the wait for a pooled
    # connection; `Database.__init__` carries the per-phase reasoning and,
    # more importantly, what the command timeout costs. In short: under
    # `dev-docs/decisions/0006-audit-write-failure.md` a failed audit write fails
    # the call, so a store slow enough to blow the statement budget now fails
    # calls it would previously have served late. That is the trade, taken
    # against a path whose two queries are one indexed SELECT and one INSERT.
    db = Database(
        settings.database_url,
        connect_timeout_seconds=settings.database_connect_timeout_seconds,
        command_timeout_seconds=settings.database_command_timeout_seconds,
        pool_timeout_seconds=settings.database_pool_timeout_seconds,
        # The ceiling, passed for the first time on 2026-09-26. Until then
        # this engine took SQLAlchemy's 5 + 10 by omission, so the number of
        # connections a replica could hold against the operator's Postgres
        # was set by a library default and could not be changed without
        # editing code. Same two values, now chosen: `services/api/settings.py`
        # says why they did not move, and `Database.__init__` carries the
        # replicas x ceiling <= max_connections arithmetic this cannot do on
        # the operator's behalf.
        pool_size=settings.database_pool_size,
        max_overflow=settings.database_max_overflow,
        # THE RESERVE, and the reason it is on THIS `Database` rather than a
        # second object passed alongside it. The two readers of the reserve
        # are the two audit writes, and both reach the store through the object
        # this line builds: `AuditMiddleware(db)` below for the completion row,
        # and the `_PendingEntry` that middleware pre-binds for the entry row.
        # A second `Database` would have to be threaded through both, plus
        # `record_data_touch`'s `ContextVar` hop, and closed on shutdown
        # separately; holding it here keeps "one `Database` per process" true
        # and makes `db.close()` dispose both engines.
        #
        # Why the audit path needs one at all: this function hands the SAME
        # `Database` to the consent lookup (`consent_db` below) and to the
        # audit middleware, so a pool at its ceiling refuses both, and the row
        # recording the refusal needed the connection that was missing.
        # `services/api/settings.py` carries why the default is 1 and why the
        # environment cannot set it to 0.
        audit_reserve_size=settings.database_audit_reserve_size,
    )

    # Consent is enforced against `AuthContext.token`, which only exists when
    # real customer authentication is configured. `has_real_customer_auth`
    # reuses the exact signal `services/api/server.py::build_server` builds
    # its `JWTVerifier` from: both jwks_uri and issuer set, or (Task 4) a
    # test-injected `auth_override`. Passing `db` into
    # `build_server` regardless would deny every consent-gated call in the
    # documented no-auth path (`Settings.for_testing()`, the local
    # docker-compose stack) -- there is no validated token there for
    # `services.api.consent` to read a subject from -- which would silently
    # break that path's own stated purpose the moment this feature landed.
    # Measured: every `tests/test_asgi_app.py` end-to-end call regressed to
    # `Unknown tool` until this was scoped to real customer auth only. This
    # condition is about consent only; it does not gate whether `db` itself
    # is built or whether audit runs.
    has_real_customer_auth = (
        settings.customer_jwks_uri is not None and settings.customer_token_issuer is not None
    ) or auth_override is not None
    consent_db = db if has_real_customer_auth else None
    # ZT-5: per-session risk tracking — factory picks in-memory (dev) or
    # Redis (production, via POSTERN_REDIS_URL).  Compatible with AWS
    # ElastiCache, Google Memorystore, Azure Cache for Redis.
    from postern_core.risk.session import create_session_store

    session_store = create_session_store()

    # Audit finding (2026-09-21): refuse to start without Redis when the
    # operator has explicitly required it. Without Redis, sessions live only
    # in process memory (lost on restart), revocation is lost on restart,
    # and JTI replay protection is lost on restart. A production deployment
    # that sets POSTERN_REQUIRE_REDIS=1 must also set POSTERN_REDIS_URL.
    #
    # THE CONDITION AND THE MESSAGE ARE UNCHANGED; only their location moved,
    # on 2026-09-26. This guard was read here and nowhere else, so an operator
    # who set the variable got the guarantee on this path and none on
    # `services/confirm`, which holds three Redis-backed stores of its own.
    # `postern_core.config.enforce_redis_requirement` is now the one
    # implementation and that service calls it too. The sentence below is the
    # read path's own consequence and is passed in rather than shared, because
    # the two services lose different things.
    #
    # THE MIDDLE CLAUSE HAS BEEN WRONG TWICE, IN TWO DIFFERENT WAYS. It first
    # read "revocation lists and JTI replay protection remain in-process per
    # replica regardless of this setting", which was true on 2026-09-21 when
    # it was written and stopped being true on 2026-09-23, when
    # `create_revocation_store` above gained a Redis backend. The 2026-09-26
    # correction fixed the revocation half and kept the jti half, which was
    # right about the storage and wrong about what was stored: "the JTI replay
    # cache has no shared backend at all" reads as a control an operator is
    # losing, and there is no such control to lose. `JtiReplayCache` sees only
    # jtis this process minted, so it cannot observe a replay in any backend.
    # Naming a per-replica limitation that costs the operator nothing is the
    # same failure as the first version in the other direction: it spends
    # their attention on a line that needs none.
    # `dev-docs/decisions/0014-jti-cache-detects-randomness-not-replay.md`
    # carries the argument; `tests/test_require_redis_guard.py`'s
    # `API_MESSAGE` pins the text.
    enforce_redis_requirement(
        consequence=(
            "This guard checks only that POSTERN_REDIS_URL is configured. It "
            "backs the session store and the ZT-7 revocation list, which are "
            "then shared across replicas. The jti cache stays per replica and "
            "should: it holds only jtis this process minted itself, so a hit "
            "there means uuid4 repeated itself, not that a token was "
            "replayed. Replay is detected by the token's recipient, which is "
            "the gateway and the domain services, and no backend configured "
            "here changes that."
        )
    )

    # ONE resolver object, handed to both `build_server` and `RiskMiddleware`
    # below. The middleware charges a call's record and account budgets to
    # whichever customer this answers, and the tools read whichever customer
    # this answers; two separate reads of the identity could disagree, and a
    # budget charged to a different customer than the one whose data was
    # returned is not a budget.
    customer_resolver = resolver or token_customer_resolver
    server = build_server(
        settings,
        customer_resolver,
        backend,
        db=consent_db,
        auth_override=auth_override,
    )
    # Task 6: an audit row per tool call, success or failure, regardless of
    # whether consent enforcement itself is active -- see the module
    # docstring and `services/api/middleware/audit.py`. Since 2026-09-18 a
    # call that reaches the operator's backend writes a second, earlier row,
    # through the `before_backend_request` hook wired above; installing this
    # middleware is what makes that hook resolvable at all, so the two go
    # together and neither is conditional.
    server.add_middleware(AuditMiddleware(db))
    # ZT-7: the revocation check, INSIDE `AuditMiddleware` and OUTSIDE
    # `RiskMiddleware`. Inside audit, because a refused call is exactly the
    # event an operator wants a row for -- it is how they confirm the
    # revocation they just wrote took effect. Outside risk, because a revoked
    # caller should be refused before spending any budget or touching the risk
    # session store: there is no reason to charge a session that is not
    # allowed to run at all.
    #
    # `customer_resolver` is the SAME object the risk layer and the tools
    # read, for the reason stated where it is built below: two separate reads
    # of the identity can disagree, and refusing one customer while returning
    # another's data is not a revocation.
    server.add_middleware(RevocationMiddleware(revocation_store, customer_resolver))
    # ZT-5: the risk layer. INSIDE `AuditMiddleware` (added second, so it
    # runs nested within it), which is what lets the audit row carry this
    # call's risk signals: `AuditMiddleware` reads `get_current_session()`
    # after this middleware returns or raises, so the contextvar must still
    # be set by then. A refusal from here therefore still writes a completion
    # row, with `outcome='raised'` and the signals that caused it.
    server.add_middleware(
        RiskMiddleware(
            session_store,
            customer_resolver,
            trusted_proxy_hops=settings.trusted_proxy_hops,
        )
    )
    app = server.http_app(
        path="/mcp",
        stateless_http=True,
        json_response=True,
        middleware=[
            # FIRST, and that means OUTERMOST: Starlette wraps
            # `user_middleware` in reverse
            # (`starlette/applications.py::build_middleware_stack`), so entry
            # zero is the last one applied and therefore the first one a
            # request reaches. That position is the point. Inside
            # `HeaderBodyValidation` this would not cover that middleware's
            # own `_drain`, which awaits `receive()` with no deadline while it
            # buffers up to `max_body_bytes` -- a body that arrives one byte
            # at a time parks a worker there, before any store or backend
            # timeout is reachable. The cost of being outermost is that the
            # body is unparsed, so an expiry cannot echo the JSON-RPC id.
            # `services/api/asgi/request_deadline.py` carries the rest,
            # including the two things this control does NOT do.
            Middleware(RequestDeadline, seconds=settings.request_deadline_seconds),
            Middleware(
                HeaderBodyValidation,
                strict=settings.strict_headers,
                max_body_bytes=settings.max_body_bytes,
            ),
        ],
    )
    # Exposed on `app.state` (Starlette's own convention for app-scoped
    # resources) so tests can observe the exact `BackendClient` instance
    # `create_app` built -- its timeout, and that `aclose` was actually
    # called on shutdown -- without reaching into `build_server`/`server`
    # internals that have no reason to hold a reference to it themselves.
    # `postern_server` and `postern_database` (Task 6) exist for the same
    # reason: proving the audit middleware is installed on the real server
    # object, and that the real database gets closed on shutdown.
    app.state.backend_client = backend
    app.state.postern_server = server
    app.state.postern_database = db
    # ZT-5, same reason as the three above: a test that wants to prove a
    # budget is enforced has to be able to seed one, and the alternative --
    # driving 500 records' worth of real calls to reach the threshold -- would
    # measure the fixtures rather than the control.
    app.state.postern_session_store = session_store
    # ZT-7, and the defect this commit exists to close: the revocation list
    # used to be a local in this function with no handle anywhere, so nothing
    # -- not a test, not an operator, not another process -- could reach it.
    # It is on `app.state` now for the same reason the four above are, and the
    # store it names is shared across replicas whenever Redis is configured.
    app.state.postern_revocation_store = revocation_store
    # The public half of the key the minter above signs with. Task 3's JWKS
    # route serves it, and it is the only handle on that key outside the
    # `BackendClient` the minter is buried in.
    app.state.postern_read_key_source = read_key_source
    _close_resources_after_fastmcp_shutdown(app, backend, db, read_key_source)
    # Plan 3 Task 3: the public half of that same key, appended to the router
    # of the object this function returns rather than served from a parent
    # Starlette app mounting this one.
    # `fastmcp/server/http.py::StarletteWithLifespan.lifespan` is a property
    # returning `self.router.lifespan_context`, and the documented parent
    # shape, `Starlette(routes=[Mount(path, app)], lifespan=app.lifespan)`,
    # evaluates that property once and stores the value it read into its own
    # router (`starlette/routing.py::Router.__init__`). A parent built before
    # the call above writes the wrapped context back therefore keeps
    # FastMCP's session manager working and every request answering normally
    # while silently dropping `backend.aclose()` and `db.close()`, with no
    # exception and no failing test. Appending here runs after the wrapper
    # and leaves `app.router.lifespan_context` untouched;
    # `tests/test_asgi_app.py` asserts both shutdown hooks still fire
    # exactly once. Order is safe because FastMCP built exactly one route
    # (`/mcp`, POST and DELETE under `stateless_http=True`) and no catch-all
    # mount, so nothing shadows this path. The route is unauthenticated by
    # construction, which is what a gateway fetching a key set needs:
    # `RequireAuthMiddleware` wraps the `/mcp` endpoint object itself
    # (`fastmcp/server/http.py::create_streamable_http_app`), not the app, and
    # `HeaderBodyValidation` returns early on any non-POST.
    app.router.routes.append(jwks_route(read_key_source))
    return app


def __getattr__(name: str) -> object:
    """PEP 562 lazy module attribute.

    A bare `app = create_app()` at import time -- as the plan originally
    drafted this file -- calls `Settings.from_env()` unconditionally, which
    needs the full production environment. That is exactly the failure
    mode the plan's own preamble warns about for `server.py` ("must not run
    at import time... or every test that imports it needs the full
    environment"), just moved one file over: measured directly, `uv run
    pytest tests/test_asgi_app.py` failed at *collection*, before any test
    ran, with `KeyError: 'POSTERN_BACKEND_BASE_URL'`, because `from
    services.api.main import create_app` executes this module's top level
    regardless of which name a test actually imports. Deferring the call to
    attribute access means `import services.api.main` (what every test
    does) is free, while `uvicorn services.api.main:app` -- which resolves
    the target the same way `getattr(import_module("services.api.main"),
    "app")` would -- still gets a real, fully configured app at process
    start, which is the only time it actually needs to exist.
    """
    if name == "app":
        return create_app()
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

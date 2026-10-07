"""MCP server assembly.

EVERY TOOL ARRIVES THROUGH THE MODULE SEAM, and this file names no tool family.
`build_server` registers whatever `services/api/tools/__init__.py`'s
`BUILTIN_READ_MODULES` and `postern_core.modules.read.load_read_modules` hand it,
by one loop, with no second path -- a built-in registered by hand could use a
FastMCP feature a module cannot express, and the seam would be second-class from
the first time someone reached for one. The cards family lives in the
`postern_cards` distribution and reaches this module only through an entry point.

THE ONE EXCEPTION IS BEHIND A FLAG. With `POSTERN_PAYMENTS_ENABLED` on,
`create_app` hands `build_server` a payments runtime and the producer's
`register` (services/api/tools/payments.py) adds its tools after the loop,
because they write a challenge row and a `ReadContext` cannot carry the
database. They are not a module, they are always consent-gated on `payments`,
and with the flag off nothing here registers them.

Three properties the loop is responsible for, each of which would be a quiet
regression rather than a loud one:

- ONE CONSENT CHECK PER DOMAIN, not per tool. `services/api/consent.py`'s module
  docstring measures five evaluations for one real call and counts the two
  accounts tools as sharing one closure; the `checks` dict below is what keeps
  that measurement describing this code.
- NO ``auth=`` AT ALL for a tool declaring no consent domain, which is a
  different thing from a check that returns True.
  `services/api/middleware/audit.py` distinguishes the two, and `start_session`
  is the one tool entitled to it.
- A DUPLICATE TOOL NAME REFUSES. FastMCP's registry is a dict keyed on the name,
  so a module declaring `accounts.list` would silently replace the shipped tool.
  `refuse_duplicate_tool_names` runs on the combined list, which is the call
  `load_read_modules`' own check cannot make.

The customer resolver is injected (design decision D3) so that:
  - there is exactly one place that answers "which customer is this?", and
  - tools are testable without an auth round trip, which FastMCP's in-process
    Client does not support (it accepts no auth argument).

`backend` is typed as `postern_core.facade.protocol.BackendReader`, a minimal
`Protocol`, not the concrete `postern_core.facade.client.BackendClient`
(Task 6): that module does not exist yet, and `build_server` never calls the
backend itself, only passes it through to tools registered in later tasks.
"""

import logging
from collections.abc import Awaitable, Callable, Iterable, Sequence

import httpx2
from fastmcp import FastMCP
from fastmcp.server.auth import AuthContext, AuthProvider
from fastmcp.server.auth.providers.jwt import JWTVerifier
from mcp.types import ToolAnnotations
from postern_core.auth.resource_uri import is_normal_https_resource
from postern_core.facade.protocol import BackendReader
from postern_core.identity import CustomerRef, CustomerResolver, TokenClaims
from postern_core.modules.read import (
    ModuleSeamViolation,
    ReadContext,
    ReadModule,
    ReadTool,
    load_read_modules,
    refuse_duplicate_tool_names,
)
from postern_core.payments import PRODUCER_TOOL_NAMES
from postern_core.store.engine import Database
from pydantic import ValidationError

from services.api.consent import consent_for
from services.api.session_verifier import SessionTokenVerifier
from services.api.settings import Settings
from services.api.tools import BUILTIN_READ_MODULES, BUILTIN_READ_MODULES_WITH_PAYMENTS
from services.api.tools import payments as payments_tools
from services.api.tools.payments import PaymentsRuntime

logger = logging.getLogger(__name__)

SERVER_INSTRUCTIONS = """\
Postern exposes read access to the customer's own bank accounts, cards and
transactions. Call `start_session` first: it returns the accounts you may
reference, which domains are consented, and the rules for this session.

Reference accounts and cards by their `ref` values, never by IBAN or card
number. Amounts always carry an explicit currency; report them as given and
do not restate them in another currency. A balance carries an `as_of` time;
a transaction carries `booked_at` instead. Transaction history defaults to
the last 30 days and must be widened explicitly.
"""


def token_customer_resolver() -> CustomerRef:
    """Production resolver: the token is the identity (handoff §6.2)."""
    from fastmcp.server.dependencies import get_access_token

    token = get_access_token()
    if token is None:
        raise PermissionError("request carries no validated access token")
    subject = token.claims.get("sub")
    if not isinstance(subject, str):
        raise PermissionError("access token carries no subject claim")
    try:
        return CustomerRef(value=subject)
    except ValidationError:
        # `subject` is minted by the token issuer; identity.py's own comment
        # is explicit that this is a provenance convention, not proof of
        # opacity -- a compromised issuer could mint a PAN-, IBAN- or
        # DNI-shaped `sub`. `CustomerRef.hide_input_in_errors` scrubs only
        # `str()`/`repr()` of the resulting `ValidationError`; its structured
        # `.errors()` still carries the raw value, and that is exactly what
        # FastMCP's own dispatcher logs if a raw `pydantic.ValidationError`
        # escapes a tool. Re-raising a plain, unchained `PermissionError`
        # keeps the raw subject out of both the wire response and the log.
        raise PermissionError(
            "access token subject is not a recognized customer reference"
        ) from None


def token_claims_provider() -> TokenClaims:
    """Production claims provider: the verified token's ``client_id`` and ``jti``.

    Read exactly as `services/api/middleware/revocation.py`'s
    `RevocationMiddleware` reads them for its revocation scopes, so a value
    stored on a challenge is the value a revocation would be keyed on. No token
    answers ``None`` for both rather than raising: the customer resolver is
    what refuses a call with no token, and it runs first.
    """
    from fastmcp.server.dependencies import get_access_token

    token = get_access_token()
    if token is None:
        return TokenClaims(client_id=None, jti=None)
    client_id = str(token.client_id) if token.client_id else None
    raw_jti = (token.claims or {}).get("jti")
    return TokenClaims(client_id=client_id, jti=raw_jti if isinstance(raw_jti, str) else None)


async def _no_consent_required(ctx: AuthContext) -> bool:
    """The `db is None` stand-in: every existing test builds a server without
    a database and must keep working unchanged, so only the consent tests
    (which always pass a real `Database`) exercise the real check.
    """
    return True


def _annotations(tool: ReadTool) -> ToolAnnotations:
    """Build the MCP annotations from a module's declared hints.

    CONSTRUCTED HERE AND NOT IN THE MODULE, so that `mcp.types.ToolAnnotations`
    -- whose import path CLAUDE.md records as a trap, since it is not
    re-exported by fastmcp -- is named in only two places a FastMCP major would
    have to reconcile: here, and the payments producer in
    services/api/tools/payments.py, which is not a module and declares all four
    hints. A module declares two booleans.
    """
    return ToolAnnotations(read_only_hint=tool.read_only, open_world_hint=tool.open_world)


def _read_modules(
    explicit: Sequence[ReadModule] | None,
    *,
    payments_enabled: bool = False,
) -> tuple[ReadModule, ...]:
    """The built-ins plus whatever is installed, or an explicit test set.

    `refuse_duplicate_tool_names` runs on the COMBINED list, which is the call
    `postern_core.modules.read.load_read_modules`' own duplicate check
    structurally cannot make: it sees only what it discovered, so a module
    shadowing `accounts.list` would pass there and silently replace a shipped
    tool here -- FastMCP's registry is a dict keyed on the name, and the second
    registration wins with no warning.
    """
    builtins = BUILTIN_READ_MODULES_WITH_PAYMENTS if payments_enabled else BUILTIN_READ_MODULES
    modules = tuple(explicit) if explicit is not None else builtins + load_read_modules()
    refuse_duplicate_tool_names(modules)
    return modules


def _refuse_producer_name_collisions(modules: Sequence[ReadModule]) -> None:
    """A read module may not declare a name the payments producer registers.

    FastMCP's registry is a dict keyed on the name, so a second registration
    of ``payments.create_payment`` would silently replace the first. Checked
    on the combined module list, for the reason `refuse_duplicate_tool_names`
    is, and only when the producer is on, so that a server built with the flag
    off accepts exactly the module set it accepted before.
    """
    claimed = sorted(
        tool.name for module in modules for tool in module.tools if tool.name in PRODUCER_TOOL_NAMES
    )
    if claimed:
        raise ModuleSeamViolation(
            f"read modules declare {claimed}, which the payments producer registers "
            "when POSTERN_PAYMENTS_ENABLED is on. A module cannot shadow a producer tool."
        )


def build_server(
    settings: Settings,
    resolver: CustomerResolver,
    backend: BackendReader | None,
    *,
    db: Database | None = None,
    auth_override: AuthProvider | None = None,
    read_modules: Sequence[ReadModule] | None = None,
    forbidden_session_thumbprints: Callable[[], Iterable[str]] = tuple,
    payments: PaymentsRuntime | None = None,
) -> FastMCP:
    has_jwks_uri = settings.customer_jwks_uri is not None
    has_issuer = settings.customer_token_issuer is not None
    if has_jwks_uri != has_issuer:
        # Exactly one set is a config typo, not a deliberate choice: neither
        # set is the documented no-auth path (`Settings.for_testing()`, the
        # local docker-compose stack); both set is normal production. Failing
        # open here -- silently returning `auth=None`, indistinguishable from
        # the deliberate no-auth path -- would serve an MCP server fronting
        # the operator's backend with no authentication at all on a forgotten
        # or misspelled environment variable. Fail startup instead.
        raise ValueError(
            "customer_jwks_uri and customer_token_issuer must both be set or "
            "both be unset (got customer_jwks_uri="
            f"{settings.customer_jwks_uri!r}, customer_token_issuer="
            f"{settings.customer_token_issuer!r})"
        )

    if has_jwks_uri and not is_normal_https_resource(settings.audience):
        # THE AUDIENCE MUST BE THE MCP SERVER'S RESOURCE URI. RFC 8707 section
        # 2 requires an absolute URI, and confirm stamps exactly this string
        # as `aud` on every session token, so the default `postern` stops
        # working in any deployment with customer authentication. That is the
        # point, and the local stack sets a URI rather than the flag.
        if not settings.allow_non_uri_audience:
            raise ValueError(
                f"POSTERN_AUDIENCE ({settings.audience!r}) must be the MCP server's "
                "resource URI: an absolute https URI with a host, a lower-case scheme and "
                "host, no default port and a non-empty path (RFC 8707 section 2), equal "
                "to services/confirm's POSTERN_SESSION_TOKEN_AUDIENCE. Set "
                "POSTERN_ALLOW_NON_URI_AUDIENCE for a local stack."
            )
        logger.warning(
            "POSTERN_ALLOW_NON_URI_AUDIENCE is set: this server accepts access tokens for "
            "the audience %r, which is not an absolute https URI. No deployment may run "
            "this way.",
            settings.audience,
        )

    auth: AuthProvider | None = None
    if has_jwks_uri and has_issuer:
        # A `JWTVerifier` whose JWKS cache is bounded: its TTL is the public
        # key TTL, unknown kids are fetched at most once per 30 seconds, and
        # concurrent misses share one fetch (`services/api/session_verifier.py`).
        # Still a `JWTVerifier` in every other respect: signature, `exp`,
        # `iss` and `aud` are the parent's checks, unchanged.
        verifier: JWTVerifier = SessionTokenVerifier(
            jwks_uri=settings.customer_jwks_uri,
            issuer=settings.customer_token_issuer,
            audience=settings.audience,
            required_scopes=None,
            cache_ttl_seconds=settings.customer_jwks_ttl_seconds,
            # This process's own READ key, by RFC 7638 thumbprint, re-read on
            # every fetch: never a session key, whatever the key set at
            # `customer_jwks_uri` says.
            forbidden_thumbprints=forbidden_session_thumbprints,
            # fastmcp's own default client for this fetch is
            # `httpx2.AsyncClient(timeout=Timeout(10.0))`, which trusts the
            # environment: `HTTP_PROXY` would let whoever runs the proxy answer
            # the key-set fetch and plant a key, and `SSL_CERT_FILE` would swap
            # the CA bundle. Same timeout, `trust_env=False`.
            http_client=httpx2.AsyncClient(timeout=httpx2.Timeout(10.0), trust_env=False),
        )
        auth = verifier
    if auth_override is not None:
        auth = auth_override

    if payments is not None and backend is None:
        raise ValueError("payments requires a backend")

    server = FastMCP(
        name="postern",
        instructions=SERVER_INSTRUCTIONS,
        auth=auth,
        cache_scope="private",
        cache_ttl=settings.cache_ttl_seconds,
        # An exception a tool raises other than a `ToolError` reaches the client
        # as `Error calling tool 'x'` and nothing else. Without this FastMCP
        # appends `: <str(e)>`, and for a SQL driver error that is the driver's
        # message with the bound value in it (and `DETAIL: Failing row contains
        # (...)`), straight into the model's channel. A `ToolError` is
        # re-raised unchanged, so the tools' own fixed refusals still arrive.
        mask_error_details=True,
    )
    if backend is not None:
        context = ReadContext(resolver=resolver, backend=backend)
        # ONE CHECK OBJECT PER DOMAIN, not per tool, and `services/api/consent.py`'s
        # module docstring is what makes that load-bearing rather than tidy: it
        # measures five evaluations of the check for one real `accounts.get_balance`
        # call, four of them from the internal `tools/list` pass, and counts
        # `accounts.list` and `accounts.get_balance` as sharing one
        # `consent_for("accounts", db)` closure while remaining two `Tool`
        # objects. A closure per tool would still hit the request-scoped cache,
        # but that measurement would stop describing this code.
        checks: dict[str, Callable[[AuthContext], Awaitable[bool]]] = {}
        modules = _read_modules(read_modules, payments_enabled=payments is not None)
        if payments is not None:
            _refuse_producer_name_collisions(modules)
        for module in modules:
            for tool in module.tools:
                handler = tool.build(context)
                if tool.consent_domain is None:
                    # No `auth=` at all, which is a different thing from a check
                    # that returns True: `services/api/middleware/audit.py` and
                    # `tests/test_audit_entry_row.py` both distinguish the two,
                    # and `start_session` is the one tool entitled to it.
                    server.tool(handler, name=tool.name, annotations=_annotations(tool))
                    continue
                if tool.consent_domain not in checks:
                    checks[tool.consent_domain] = (
                        consent_for(tool.consent_domain, db)
                        if db is not None
                        else _no_consent_required
                    )
                server.tool(
                    handler,
                    name=tool.name,
                    annotations=_annotations(tool),
                    auth=checks[tool.consent_domain],
                )
        if payments is not None:
            # The one registration that does not come from a module, and only
            # with POSTERN_PAYMENTS_ENABLED on (see the module docstring).
            payments_tools.register(server, resolver, backend, payments)
    return server

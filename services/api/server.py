"""MCP server assembly.

The customer resolver is injected (design decision D3) so that:
  - there is exactly one place that answers "which customer is this?", and
  - tools are testable without an auth round trip, which FastMCP's in-process
    Client does not support (it accepts no auth argument).

`backend` is typed as `postern_core.facade.protocol.BackendReader`, a minimal
`Protocol`, not the concrete `postern_core.facade.client.BackendClient`
(Task 6): that module does not exist yet, and `build_server` never calls the
backend itself, only passes it through to tools registered in later tasks.
"""

from fastmcp import FastMCP
from fastmcp.server.auth import AuthContext, AuthProvider
from fastmcp.server.auth.providers.jwt import JWTVerifier
from postern_core.facade.protocol import BackendReader
from postern_core.identity import CustomerRef, CustomerResolver
from postern_core.store.engine import Database
from pydantic import ValidationError

from services.api.consent import consent_for
from services.api.settings import Settings
from services.api.tools import accounts as accounts_tools
from services.api.tools import bootstrap as bootstrap_tools
from services.api.tools import cards as cards_tools
from services.api.tools import transactions as transactions_tools

SERVER_INSTRUCTIONS = """\
Postern exposes read access to the customer's own bank accounts, cards and
transactions. Call `banking_start_session` first: it returns the accounts you
may reference, which domains are consented, and the rules for this session.

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


async def _no_consent_required(ctx: AuthContext) -> bool:
    """The `db is None` stand-in: every existing test builds a server without
    a database and must keep working unchanged, so only the consent tests
    (which always pass a real `Database`) exercise the real check.
    """
    return True


def build_server(
    settings: Settings,
    resolver: CustomerResolver,
    backend: BackendReader | None,
    *,
    db: Database | None = None,
    auth_override: AuthProvider | None = None,
) -> FastMCP:
    has_jwks_uri = settings.customer_jwks_uri is not None
    has_issuer = settings.customer_token_issuer is not None
    if has_jwks_uri != has_issuer:
        # Exactly one set is a config typo, not a deliberate choice: neither
        # set is the documented no-auth path (`Settings.for_testing()`, the
        # local docker-compose stack); both set is normal production. Failing
        # open here -- silently returning `auth=None`, indistinguishable from
        # the deliberate no-auth path -- would serve a bank-facing MCP server
        # with no authentication at all on a forgotten or misspelled
        # environment variable. Fail startup instead.
        raise ValueError(
            "customer_jwks_uri and customer_token_issuer must both be set or "
            "both be unset (got customer_jwks_uri="
            f"{settings.customer_jwks_uri!r}, customer_token_issuer="
            f"{settings.customer_token_issuer!r})"
        )

    auth: AuthProvider | None = None
    if has_jwks_uri and has_issuer:
        auth = JWTVerifier(
            jwks_uri=settings.customer_jwks_uri,
            issuer=settings.customer_token_issuer,
            audience=settings.audience,
            required_scopes=None,
        )
    if auth_override is not None:
        auth = auth_override

    server = FastMCP(
        name="postern",
        instructions=SERVER_INSTRUCTIONS,
        auth=auth,
        cache_scope="private",
        cache_ttl=settings.cache_ttl_seconds,
    )
    if backend is not None:
        bootstrap_tools.register(server, resolver, backend)
        accounts_check = consent_for("accounts", db) if db is not None else _no_consent_required
        transactions_check = (
            consent_for("transactions", db) if db is not None else _no_consent_required
        )
        cards_check = consent_for("cards", db) if db is not None else _no_consent_required
        accounts_tools.register(server, resolver, backend, accounts_check)
        transactions_tools.register(server, resolver, backend, transactions_check)
        cards_tools.register(server, resolver, backend, cards_check)
    return server

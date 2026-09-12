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
from fastmcp.server.auth.providers.jwt import JWTVerifier
from postern_core.facade.protocol import BackendReader
from postern_core.identity import CustomerRef, CustomerResolver
from pydantic import ValidationError

from services.api.settings import Settings

SERVER_INSTRUCTIONS = """\
Postern exposes read access to the customer's own bank accounts, cards and
transactions. Call `banking_start_session` first: it returns the accounts you
may reference, which domains are consented, and the rules for this session.

Reference accounts and cards by their `ref` values, never by IBAN or card
number. Amounts are always structured with an explicit currency and an `as_of`
timestamp; report them as given and do not restate them in another currency.
Transaction history defaults to the last 30 days and must be widened explicitly.
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


def build_server(
    settings: Settings,
    resolver: CustomerResolver,
    backend: BackendReader | None,
) -> FastMCP:
    auth = None
    if settings.customer_jwks_uri and settings.customer_token_issuer:
        auth = JWTVerifier(
            jwks_uri=settings.customer_jwks_uri,
            issuer=settings.customer_token_issuer,
            audience=settings.audience,
            required_scopes=None,
        )

    return FastMCP(
        name="postern",
        instructions=SERVER_INSTRUCTIONS,
        auth=auth,
        cache_scope="private",
        cache_ttl=settings.cache_ttl_seconds,
    )

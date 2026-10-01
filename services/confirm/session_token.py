"""The layer-1 access token ``POST /token`` issues, and the key that signs it.

TWO LAYERS, AND THIS IS THE FIRST ONE. Handoff section 7.1 separates the AI
client talking to the MCP server (layer 1) from the MCP server talking to the
backend with a 60-second delegation token (layer 2). This module mints only
the first kind: its ``aud`` is the MCP server ``services/api`` serves, its key
signs nothing else, and it carries no ``act`` claim, so no domain service and
no Istio gateway configured for layer 2 accepts it.

NOT ``InternalTokenMinter``. That class's delegation shape -- ``act``, a fixed
60-second life, a domain-service audience -- is exactly the conflation
``dev-docs/device-grant-session-token-spec.md`` removes, so reusing it would
put the shape back one keyword argument away.

TWO STEPS, ``prepare`` then ``sign``, because ``POST /token`` records the
``jti`` in the refresh-session store BEFORE the token exists: a recall at
``POST /scan`` that finds the family must be able to name every token it can
ever have issued. ``prepare`` draws the ``jti`` and reads the clock once;
``sign`` only signs.
"""

from __future__ import annotations

import time
import uuid
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any, Protocol

# Re-exported: the thumbprint moved to the shared library on 2 October 2026,
# so `services/api` can drop its own read key from what it fetches as session
# keys (`.importlinter` forbids it importing this service).
from postern_core.auth.jwk_thumbprint import THUMBPRINT_MEMBERS as THUMBPRINT_MEMBERS
from postern_core.auth.jwk_thumbprint import jwk_thumbprints as jwk_thumbprints
from postern_core.auth.keys import KeySource, choose_key_source

# Re-exported: the lifetime moved to the shared library on 2 October 2026, so
# `services/api`'s verifier refuses an `exp` beyond the same number.
from postern_core.auth.session_lifetime import (
    ACCESS_TOKEN_LIFETIME_SECONDS as ACCESS_TOKEN_LIFETIME_SECONDS,
)
from postern_core.identity import CustomerRef

from services.confirm.settings import ConfirmSettings


@dataclass(frozen=True, slots=True)
class SessionClaims:
    """Every claim one access token carries, frozen before it is signed."""

    iss: str
    aud: str
    sub: str
    client_id: str
    scope: str
    sid: str
    jti: str
    iat: int

    @property
    def exp(self) -> int:
        """``iat`` plus `ACCESS_TOKEN_LIFETIME_SECONDS`."""
        return self.iat + ACCESS_TOKEN_LIFETIME_SECONDS

    def as_claims(self) -> dict[str, Any]:
        """The JWT claim set, and nothing else.

        ``client_id_verified`` is ``False`` on every token, because the
        ``client_id`` beside it is whatever the browser typed at
        ``POST /device_authorization``: the marking ``POST /scan`` already puts
        in its response. No ``act``, no ``nbf``, no PII.
        """
        return {
            "iss": self.iss,
            "aud": self.aud,
            "sub": self.sub,
            "client_id": self.client_id,
            "client_id_verified": False,
            "scope": self.scope,
            "sid": self.sid,
            "jti": self.jti,
            "iat": self.iat,
            "exp": self.exp,
        }


class SessionTokenMinter:
    """Mints layer-1 access tokens over the SESSION key and no other."""

    def __init__(self, *, issuer: str, audience: str, key_source: KeySource) -> None:
        self._issuer = issuer
        self._audience = audience
        self._key_source = key_source

    def prepare(
        self, *, customer: CustomerRef, client_id: str, scope: str, sid: str
    ) -> SessionClaims:
        """Draw a ``jti`` and read the clock, once, and return frozen claims.

        The ``jti`` is ``uuid.uuid4()`` and is never accepted from a caller,
        for the reason ``InternalTokenMinter.mint_with_jti``'s docstring gives:
        a caller-chosen id is a collision someone else can arrange. ``sub``
        comes from a ``CustomerRef``, so a value that is not a customer
        reference cannot reach a token.
        """
        return SessionClaims(
            iss=self._issuer,
            aud=self._audience,
            sub=customer.value,
            client_id=client_id,
            scope=scope,
            sid=sid,
            jti=str(uuid.uuid4()),
            iat=int(time.time()),
        )

    def sign(self, claims: SessionClaims) -> str:
        """``claims`` as an RS256 compact JWS.

        Under Vault this is a transit request and can raise
        ``VaultTransitError``; it never returns an unsigned token.
        """
        return self._key_source.sign(claims.as_claims())


class PublishesJwks(Protocol):
    """The one capability the material check needs: a public key set."""

    def public_jwks(self) -> Any: ...


def refuse_shared_key_material(
    *,
    session: PublishesJwks,
    others: Iterable[tuple[str, PublishesJwks]],
    session_variable: str,
) -> None:
    """Refuse a session key whose PUBLIC half is also the write key's.

    Compares what each source publishes, so it holds for a copied PEM, a
    hardlink, a case-different path and a Vault transit key alike, none of
    which the path and name checks in ``check_session_token_settings`` can see.
    ``others`` pairs each other key's variable name with its source; since
    the layer-1 session token this service holds no read key, so its one
    caller passes the write key alone.
    ``ValueError`` names both variables and carries no key bytes.

    A session source whose own set yields NO thumbprint (an unsupported
    ``kty``, a missing member, no keys at all) is refused too: an empty set
    overlaps nothing, so the comparison would pass without having compared.
    """
    mine = jwk_thumbprints(session.public_jwks())
    if not mine:
        raise ValueError(
            f"{session_variable}: the session key's public key could not be fingerprinted "
            "(no RSA, EC or OKP key with its RFC 7638 members in what it publishes), so it "
            "cannot be shown to differ from the write key. Refusing to start."
        )
    for variable, source in others:
        if mine & jwk_thumbprints(source.public_jwks()):
            raise ValueError(
                f"{session_variable} and {variable} resolve to the same key MATERIAL. The "
                "session key must be a different key from the write key; a copied file, "
                "a hardlink or one Vault key under two names is still one key."
            )


def build_session_minter(settings: ConfirmSettings) -> tuple[SessionTokenMinter, KeySource]:
    """The session minter plus the `KeySource` behind it, for the JWKS route.

    The same one-key-in, one-source-out call ``build_write_minter`` makes, so
    the SESSION key inherits every rule the other two keys have: Vault when
    ``POSTERN_VAULT_ADDR`` is set, a PEM when ``POSTERN_SESSION_KEY_PEM_PATH``
    is, a generated key with the ephemeral warning otherwise, and a refusal at
    startup when both are set.
    """
    key_source = choose_key_source(
        role="SESSION",
        kid=settings.session_key_kid,
        vault=settings.vault,
        vault_key_name=settings.vault_session_key_name,
        pem_path=settings.session_key_pem_path,
        pem_env_var="POSTERN_SESSION_KEY_PEM_PATH",
    )
    minter = SessionTokenMinter(
        issuer=settings.session_token_issuer,
        audience=settings.session_token_audience,
        key_source=key_source,
    )
    return minter, key_source

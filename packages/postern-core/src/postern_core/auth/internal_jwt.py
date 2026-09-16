"""Minting the token for one internal hop (handoff §7.2).

Pure: a key plus claims in, a signed string out, no I/O. Vault lives behind
`KeySource` and never appears here.

One instance per Vault role. The API service constructs the READ minter only;
the confirm service constructs the WRITE minter only. There is deliberately no
code path that gives one process both, which is what makes the separation an
infrastructure property rather than a code-review promise.
"""

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from joserfc import jwt
from joserfc.jwt import Claims

from postern_core.auth.keys import KeySource
from postern_core.identity import CustomerRef

_LIFETIME = timedelta(seconds=60)


@dataclass(frozen=True)
class InternalTokenMinter:
    """Turns a `KeySource` plus a customer, an audience and a scope into an
    RFC 8693 delegation token: the customer as `sub`, this service as
    `act.sub`, a 60 second life. No PII: `sub` is the opaque `CustomerRef`,
    never a raw string, because tokens land in logs and traces."""

    issuer: str
    key_source: KeySource
    actor: str = "svc:postern"

    def mint(
        self,
        *,
        subject: CustomerRef,
        audience: str,
        scope: str,
        consent_id: str | None = None,
        client_id: str | None = None,
        challenge_id: str | None = None,
    ) -> str:
        now = datetime.now(UTC)
        claims: Claims = {
            "iss": self.issuer,
            "sub": subject.value,
            "act": {"sub": self.actor},
            "aud": audience,
            "scope": scope,
            "iat": int(now.timestamp()),
            "exp": int((now + _LIFETIME).timestamp()),
            "jti": str(uuid.uuid4()),
        }
        for name, value in (
            ("consent_id", consent_id),
            ("client_id", client_id),
            ("challenge_id", challenge_id),
        ):
            if value is not None:
                claims[name] = value

        key = self.key_source.signing_key()
        return jwt.encode({"alg": "RS256", "kid": key.kid}, claims, key)

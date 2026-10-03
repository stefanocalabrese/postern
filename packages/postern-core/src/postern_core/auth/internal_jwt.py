"""Minting the token for one internal hop (handoff §7.2).

Claims in, a signed string out. Vault lives behind `KeySource` and never
appears here.

THIS FUNCTION IS NO LONGER PURE, AND THE LINE THAT SAID IT WAS IS GONE. It
read "a key plus claims in, a signed string out, no I/O" until 29 September
2026, which was true of the two local key sources and stopped being true the
moment `postern_core.auth.vault.VaultTransitKeySource` existed: under it,
`mint` performs a synchronous HTTP round trip to Vault, measured at 1.8ms over
loopback against 0.9ms for the in-process signature it replaces. Nothing about
the shape of this module changed -- it still knows nothing about where the
signature happens -- but a caller reading "no I/O" and concluding that `mint`
cannot block, cannot time out and cannot raise a network error would be wrong
on all three. It can raise `VaultTransitError`, and it does so rather than
returning an unsigned token, which is the direction this path has to fail in.

TWO METHODS, ONE BODY. `mint` returns the token. `mint_with_jti` returns the
token and the ``jti`` that was signed into it, for the one caller that needs
the second value. The wider return went on a new method rather than replacing
`mint`. `ReadTokenMinter` is the only caller anywhere that wants the jti, and
it is now the only caller of `mint_with_jti`. What `mint` keeps are the callers
that want a string and nothing else: `services/confirm/minter.py`'s
`WriteTokenMinter`, the device grant's token endpoint in
`services/confirm/device_auth.py`, and every `mint` call across
`tests/test_internal_jwt.py`, `tests/test_confirm_service.py` and
`tests/test_key_split_is_a_property.py`. Widening the method all of those use,
to serve the one that is not among them, buys a `.token` nobody reads at every
one of those sites.

One instance per Vault role. The API service constructs the READ minter only;
the confirm service constructs the WRITE minter only. There is deliberately no
code path that gives one process both, which is what makes the separation an
infrastructure property rather than a code-review promise.
"""

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from joserfc.jwt import Claims

from postern_core.auth.keys import KeySource
from postern_core.identity import CustomerRef

_LIFETIME = timedelta(seconds=60)


@dataclass(frozen=True, slots=True)
class MintedToken:
    """A signed token beside the ``jti`` it carries.

    A named pair and not a `tuple[str, str]` on purpose: both fields are
    strings, so a transposed unpacking would type-check, would sign correctly,
    and would hand `JtiReplayCache` an entire JWT as a jti. The names make that
    mistake unwritable.
    """

    # repr=False: a bearer value, which a formatted exception or log line would print.
    token: str = field(repr=False)
    jti: str


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
        """The signed token, for the callers that want nothing else."""
        return self.mint_with_jti(
            subject=subject,
            audience=audience,
            scope=scope,
            consent_id=consent_id,
            client_id=client_id,
            challenge_id=challenge_id,
        ).token

    def mint_with_jti(
        self,
        *,
        subject: CustomerRef,
        audience: str,
        scope: str,
        consent_id: str | None = None,
        client_id: str | None = None,
        challenge_id: str | None = None,
    ) -> MintedToken:
        """The signed token and its ``jti``, for a caller that needs both.

        The jti exists here as a local for the two statements between drawing
        it and signing it, and used to be unreachable after that. The one
        caller that wants it, `ReadTokenMinter` feeding `JtiReplayCache`,
        recovered it by reimporting the published JWKS and running an RS256
        verification over a token this method had just produced: measured at
        42us per backend call against the 910us the signature below costs, to
        read back a value that was in scope here. Reporting it outward is the
        whole of this method.

        The jti is still drawn here and never accepted from a caller. An
        argument would have been additive and would have changed no call site,
        and it would also have let one caller pass a constant into a claim the
        minter is supposed to guarantee is unique per token.
        """
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

        # THE ONE LINE THAT MADE VAULT POSSIBLE. This was
        # ``key = self.key_source.signing_key()`` followed by ``jwt.encode(...,
        # key)``, which required the seam to hand this function a private key
        # and therefore required the key to be in this process. `KeySource.sign`
        # returns the token instead, so where the signature happens is the
        # implementation's business: in process for `GeneratedKeySource` and
        # `FileKeySource`, inside Vault for
        # `postern_core.auth.vault.VaultTransitKeySource`. Nothing else in this
        # function changed, and nothing above it did.
        token = self.key_source.sign(claims)
        # `claims["jti"]` and not a second `uuid4()`: this is the value that
        # was signed, which is the only value a jti consumer can use.
        return MintedToken(token=token, jti=str(claims["jti"]))

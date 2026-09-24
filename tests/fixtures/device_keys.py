"""Enrolled device keys and approval signatures, for the write-path suites.

Every test that drives ``POST /challenges/{id}/approve`` past the signature
check needs two things the repository deliberately does not ship: a key pair,
and an enrolment record naming its public half. This module makes both, and is
the only place in the tree that signs an approval.

THE SIGNING HELPERS CALL THE PRODUCTION ENCODER, and that is a real weakness
worth naming rather than hiding: a bug in
`postern_core.auth.approval_signature`'s ``canonical_approval_message`` would
be invisible to any test that signs through it, because the signer and the
verifier would agree on the same wrong bytes. What covers that is
``tests/test_approval_signature.py``, which pins the exact bytes of a known
challenge as a literal and rebuilds one message by hand, so the encoding has
an independent witness. These helpers exist so the OTHER suites can express
"a valid approval" in one line without every one of them re-deriving it.
"""

from __future__ import annotations

import base64
from datetime import datetime
from typing import Any

from joserfc.jwa import EdDSAAlgorithm
from joserfc.jwk import OKPKey
from postern_core.auth.approval_signature import canonical_approval_message
from postern_core.auth.device_keys import EnrolledDeviceKey, InMemoryDeviceKeyStore
from postern_core.store.challenges import get_challenge
from postern_core.store.engine import Database
from postern_core.store.models import ChallengeRecord

_ED25519 = EdDSAAlgorithm()


def device_key(kid: str = "phone-ios") -> tuple[OKPKey, EnrolledDeviceKey]:
    """A fresh Ed25519 key pair as ``(private, enrolled public half)``.

    Ed25519 generation is microseconds, unlike the RSA pairs these suites
    build once per module, so nothing here is worth caching.
    """
    private = OKPKey.generate_key("Ed25519")
    public = OKPKey.import_key(private.as_dict(private=False))
    return private, EnrolledDeviceKey(kid=kid, key=public)


def enrolled_store(
    customer_ref: str, *keys: EnrolledDeviceKey, **others: tuple[EnrolledDeviceKey, ...]
) -> InMemoryDeviceKeyStore:
    """A store enrolling ``keys`` for ``customer_ref``, plus any other customers."""
    enrolment: dict[str, tuple[EnrolledDeviceKey, ...]] = {customer_ref: tuple(keys)}
    enrolment.update(others)
    return InMemoryDeviceKeyStore(enrolment)


def sign_fields(
    private: OKPKey,
    *,
    challenge_id: str,
    customer_ref: str,
    tool_name: str,
    payload: dict[str, Any],
    expires_at: datetime,
) -> str:
    """The wire-form signature over these exact fields.

    Takes the five fields rather than a row on purpose: a test that must
    produce a signature over the WRONG content -- another challenge's id, an
    altered amount -- changes one argument here instead of building a second
    row it does not otherwise need.
    """
    message = canonical_approval_message(
        challenge_id=challenge_id,
        customer_ref=customer_ref,
        tool_name=tool_name,
        payload=payload,
        expires_at=expires_at,
    )
    return sign_message(private, message)


def sign_message(private: OKPKey, message: bytes) -> str:
    """Raw Ed25519 over arbitrary bytes, in the 86-character wire form."""
    return base64.urlsafe_b64encode(_ED25519.sign(message, private)).rstrip(b"=").decode("ascii")


def sign_row(private: OKPKey, record: ChallengeRecord) -> str:
    """The signature the customer's phone would produce for this stored row."""
    return sign_fields(
        private,
        challenge_id=record.challenge_id,
        customer_ref=record.customer_ref,
        tool_name=record.tool_name,
        payload=record.payload,
        expires_at=record.expires_at,
    )


async def approval_body(
    db: Database, challenge_id: str, private: OKPKey, **extra: Any
) -> dict[str, Any]:
    """A valid approval body for a challenge that is already in the database.

    Reads the row and signs what it actually holds, which is the only way to
    sign a challenge whose ``expires_at`` a test rewrote after creating it --
    and is what the operator's push payload has to do as well.
    """
    async with db.sessionmaker() as session:
        record = await get_challenge(session, challenge_id)
        assert record is not None, f"{challenge_id} is not in the database"
        return {"signature": sign_row(private, record), **extra}

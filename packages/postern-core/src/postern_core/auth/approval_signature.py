"""What the customer's phone signs, and how the server checks it.

THE ONE LOAD-BEARING PROPERTY: the bytes that are verified are built from the
STORED CHALLENGE ROW and never from the request. CLAUDE.md states it for the
confirmation payload -- "built server-side from the stored challenge row" --
and this applies it to the signature, because a signature over something the
caller chose proves only that the caller can sign what it chose. The approval
handler holds the row (`postern_core.store.challenges`'s ``get_challenge``
returned it) and passes its columns here; the request body contributes exactly
one value to this module, the signature itself.

WHAT THE MESSAGE COVERS, and why each field is in it:

``challenge_id``
    Which approval this is. Without it, one signature would approve every
    challenge that happened to carry the same amount and payee.
``customer_ref``
    Whose approval it is. Without it, a signature made by a device enrolled to
    one customer would verify against another customer's challenge if the two
    ever carried identical contents -- and the key set is per customer, so the
    only thing stopping that today is the ownership check one layer up.
``tool_name``
    What the approval authorises. ``payments.create_payment`` and
    ``cards.freeze`` carrying the same payload must not be interchangeable.
``payload``
    The amount, the payee, the account: what the human was shown. This is the
    field that makes the control worth having, because it is the one an
    injected agent would want to change.
``expires_at``
    The deadline in force when the signature was made. A challenge's deadline
    is written once at creation and never updated, so a signature cannot be
    carried across a "refreshed" challenge: refreshing means a new row, which
    means a new ``challenge_id`` and a new deadline, and the old signature
    verifies against neither.

WHAT BINDS ONE SIGNATURE TO ONE APPROVAL ATTEMPT, stated plainly because
"replay" has two meanings here and only one of them is closed by the bytes.
Ed25519 is deterministic, so one device signing one challenge produces one
signature, every time; the same string presented twice is the NORMAL case
(MCP ``2026-07-28`` removed SSE resumability, so a client re-issuing a dropped
request is specified behaviour). What makes a second presentation harmless is
not the signature but the row: ``services/confirm/callback.py`` claims the
challenge with a conditional ``UPDATE`` whose ``WHERE`` carries ``status =
'pending'`` and ``expires_at > now()``, so exactly one presentation can ever
move it, and every later one gets 409 or 410 having changed nothing. THE UNIT
OF SINGLE USE IS THE CHALLENGE ROW, NOT THE SIGNATURE.

A server-generated nonce mixed into the message would move that property into
the bytes, and was rejected: it needs a column to store it in (this change
carries no migration) and a round trip to hand it to the phone, and it would
buy nothing that the conditional ``UPDATE`` does not already hold under a row
lock in PostgreSQL.

THE ENCODING, and why two different challenges cannot produce the same bytes.
Every value is type-tagged and length-prefixed, recursively:

====================  =============================================
value                 encoding
====================  =============================================
``null``              ``n0:,``
``true`` / ``false``  ``b4:true,`` / ``b5:false,``
integer               ``i`` + netstring of its decimal digits
string                ``s`` + netstring of its UTF-8 bytes
list                  ``l`` + netstring of its items' encodings
object                ``d`` + netstring of (netstring(key) + value)
                      pairs, keys sorted by their UTF-8 bytes
====================  =============================================

A netstring is ``<decimal length>:<bytes>,`` (Bernstein). Because the length
of every element precedes it, no concatenation of one tree can be read as
another: ``{"a": "bc"}`` and ``{"ab": "c"}`` differ at the first length byte,
where a delimiter-joined encoding would have to hope no value contains the
delimiter. Keys are sorted, so a dict's iteration order -- which is insertion
order in Python and unordered in ``JSONB`` -- cannot change the bytes. The
whole is prefixed with `APPROVAL_DOMAIN`, so a signature over these bytes
cannot be replayed into any other protocol that asks the same device key to
sign something, and the ``v1`` in it is how a future encoding change becomes a
different message rather than a silent one.

FLOATS ARE REFUSED, not formatted. A float has no single spelling that every
language agrees on -- the phone signing this is not running Python -- and a
canonicalisation that depends on one is a canonicalisation that will disagree
with the signer one day, in production, on a payment. ``JSONB`` can hold one,
so this is a real refusal rather than a theoretical one: it raises
`UncanonicalChallengeError`, ``services/confirm/callback.py`` records the
exception type on an audit row, the caller gets a 500 and the challenge is
untouched. Money amounts in this tree are strings ("EUR 340.00"), which is
what `postern_core.store.challenges`'s ``create_challenge`` docstring already
shows and what a currency amount should be anyway.

THE WIRE FORM OF THE SIGNATURE is 86 characters of unpadded base64url, which
is the only spelling of 64 bytes this module accepts. Rejecting padded and
non-canonical spellings costs a client nothing and keeps the stored evidence
from having two forms of one approval.
"""

from __future__ import annotations

import base64
import re
from datetime import UTC, datetime
from typing import Any

from joserfc.jwa import EdDSAAlgorithm

from postern_core.auth.device_keys import EnrolledDeviceKey

#: Domain separation. Prepended to every message this module produces, so a
#: device key that is ever asked to sign anything else -- a login challenge, a
#: pairing confirmation -- cannot have that signature replayed as an approval.
#: The version is part of the domain: changing the encoding below means
#: changing this string, which makes every old signature verify against
#: nothing rather than against a message someone has to reason about.
APPROVAL_DOMAIN = b"postern.device-approval.v1"

#: Ed25519 signatures are always 64 bytes, so the wire form is always 86
#: unpadded base64url characters. An exact length is a real check rather than
#: a sanity one: it refuses a truncated signature before any key is touched.
SIGNATURE_BYTES = 64
_SIGNATURE_CHARS = re.compile(r"\A[A-Za-z0-9_-]{86}\Z")

# One instance, built once. `EdDSAAlgorithm` holds no state: `verify` reads
# the key it is handed and nothing else. Its `security_warning` attribute
# ("EdDSA is deprecated via RFC 9864") is about the JWS ALGORITHM NAME -- RFC
# 9864 replaces the `"EdDSA"` alg identifier with curve-specific `"Ed25519"`
# -- and says nothing about the primitive. Nothing here produces a JWS, so no
# algorithm identifier is negotiated, transmitted or trusted at all: the curve
# is fixed by `postern_core.auth.device_keys`'s ``REQUIRED_CURVE`` at
# enrolment. That also closes the algorithm-confusion shape this repository
# already knows from JWTs, because there is no `alg` header anywhere on this
# path for an attacker to set.
_ED25519 = EdDSAAlgorithm()


class UncanonicalChallengeError(ValueError):
    """This stored challenge cannot be serialised to one unambiguous message.

    Raised for a payload this module refuses to guess at -- a float, a
    non-string object key, a value of a type JSON cannot carry -- and for a
    deadline with no time zone. Every one of those is a defect in whatever
    wrote the row rather than anything a caller did, which is why it is an
    exception and not a refusal: ``services/confirm/callback.py``'s
    ``except Exception`` records the type on an audit row, answers 500, and
    leaves the challenge exactly as it found it.

    The offending value is NEVER in the message. A challenge payload carries
    the amount and the payee, and this exception's text reaches a log.
    """


def canonical_approval_message(
    *,
    challenge_id: str,
    customer_ref: str,
    tool_name: str,
    payload: dict[str, Any],
    expires_at: datetime,
) -> bytes:
    """The exact bytes an enrolled device must sign to approve this challenge.

    Every argument comes from the stored ``challenges`` row. Nothing here
    accepts a request body, and the signature is not an argument: a caller
    must not be able to influence what they are proving they signed.

    Raises:
        UncanonicalChallengeError: if the row cannot be encoded unambiguously.
    """
    return (
        APPROVAL_DOMAIN
        + b"\n"
        + _encode(
            {
                "challenge_id": challenge_id,
                "customer_ref": customer_ref,
                "expires_at": _instant(expires_at),
                "payload": payload,
                "tool_name": tool_name,
            }
        )
    )


def decode_signature(presented: str) -> bytes | None:
    """The 64 raw bytes behind an 86-character base64url signature, or ``None``.

    ``None`` means the string is not a spelling of an Ed25519 signature at
    all, which the caller answers the same way it answers one that does not
    verify -- with a different audit ``detail``, because a client that cannot
    encode a signature and a client presenting one that fails are different
    events for whoever reads the table.

    The round trip at the end refuses a NON-CANONICAL spelling: base64
    ignores the unused low bits of its final character, so 64 bytes have 86
    characters that decode to them and four spellings of the last one. All
    four would verify; only one is stored. One approval, one string.
    """
    if not _SIGNATURE_CHARS.match(presented):
        return None
    raw = base64.urlsafe_b64decode(presented + "==")
    if len(raw) != SIGNATURE_BYTES:  # pragma: no cover - fixed by the length above
        return None
    if base64.urlsafe_b64encode(raw).rstrip(b"=") != presented.encode("ascii"):
        return None
    return raw


def verify_approval_signature(
    *,
    keys: tuple[EnrolledDeviceKey, ...],
    message: bytes,
    signature: bytes,
) -> EnrolledDeviceKey | None:
    """The enrolled key this signature was made with, or ``None`` if none was.

    Every key the customer has enrolled is tried, because a customer has more
    than one phone and because letting the REQUEST name a key would hand the
    caller an input this control is built not to take. The cost is bounded by
    `postern_core.auth.device_keys`'s ``MAX_KEYS_PER_CUSTOMER``.

    ``joserfc``'s ``EdDSAAlgorithm.verify`` returns ``False`` for a bad
    signature rather than raising, having caught ``cryptography``'s
    ``InvalidSignature`` itself; nothing here turns that into a truth value a
    second time.
    """
    for enrolled in keys:
        if _ED25519.verify(message, signature, enrolled.key):
            return enrolled
    return None


# ---------------------------------------------------------------------------
# The encoding. Every branch is length-prefixed and type-tagged; see the
# module docstring's table.
# ---------------------------------------------------------------------------


def _netstring(raw: bytes) -> bytes:
    """``<length>:<bytes>,`` -- the reason no two trees can share an encoding."""
    return str(len(raw)).encode("ascii") + b":" + raw + b","


def _encode(value: object) -> bytes:
    # `bool` BEFORE `int`, because `bool` is a subclass of it: without this
    # order `True` encodes as `i1:1,` and becomes indistinguishable from the
    # integer 1, which is exactly the kind of collision the tagging exists to
    # prevent.
    if value is None:
        return b"n" + _netstring(b"")
    if isinstance(value, bool):
        return b"b" + _netstring(b"true" if value else b"false")
    if isinstance(value, int):
        return b"i" + _netstring(str(value).encode("ascii"))
    if isinstance(value, str):
        return b"s" + _netstring(_utf8(value))
    if isinstance(value, list | tuple):
        return b"l" + _netstring(b"".join(_encode(item) for item in value))
    if isinstance(value, dict):
        return b"d" + _netstring(b"".join(_encode_pair(key, item) for key, item in _sorted(value)))
    raise UncanonicalChallengeError(
        f"a challenge payload carries a {type(value).__name__}, which has no single "
        "spelling every signer would agree on. Floats are the case this rejects in "
        "practice: the phone signing an approval is not running Python, and a "
        "canonicalisation that depends on one language's float formatting will "
        "disagree with the signer eventually, on a payment. Amounts are strings here."
    )


def _sorted(value: dict[Any, Any]) -> list[tuple[str, Any]]:
    """The object's pairs, ordered by the UTF-8 bytes of their keys.

    Sorted by BYTES and not by ``str`` order, so the ordering does not depend
    on Python's code-point comparison for anything outside ASCII. Non-string
    keys are refused: ``JSONB`` cannot produce one, and a tree that reached
    here with one came from somewhere other than the database.
    """
    for key in value:
        if not isinstance(key, str):
            raise UncanonicalChallengeError(
                f"a challenge payload carries a {type(key).__name__} object key; only "
                "strings can be ordered the same way by every signer."
            )
    return sorted(value.items(), key=lambda pair: _utf8(pair[0]))


def _encode_pair(key: str, value: object) -> bytes:
    return _netstring(_utf8(key)) + _encode(value)


def _utf8(value: str) -> bytes:
    try:
        return value.encode("utf-8")
    except UnicodeEncodeError as exc:  # pragma: no cover - PostgreSQL rejects these first
        raise UncanonicalChallengeError(
            "a challenge carries a string that is not encodable as UTF-8 "
            f"({type(exc).__name__}), so it has no canonical byte form."
        ) from exc


def _instant(value: datetime) -> str:
    """``2026-09-24T10:11:12.131415Z`` -- one spelling of one instant.

    Always UTC, always six fractional digits, always the ``Z`` suffix. The
    alternatives were both worse: an offset-bearing form makes the same
    instant spell two ways, and an epoch integer costs the operator's push
    payload a value a human can read back off the phone's screen during an
    incident.

    A naive datetime is refused rather than assumed to be UTC.
    ``challenges.expires_at`` is ``DateTime(timezone=True)``
    (`postern_core.store.models`'s ``ChallengeRecord``), so a naive one means
    the row was not loaded through that column, and guessing a zone is how
    the server and the phone come to disagree about a deadline by an hour.
    """
    if value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
        raise UncanonicalChallengeError(
            "a challenge deadline carries no time zone, so it names no instant. "
            "challenges.expires_at is DateTime(timezone=True); a naive value here "
            "means this row did not come from that column."
        )
    utc = value.astimezone(UTC)
    return f"{utc:%Y-%m-%dT%H:%M:%S}.{utc.microsecond:06d}Z"

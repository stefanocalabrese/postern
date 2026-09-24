"""The approval signature check: where it runs, and what each refusal means.

WHAT THIS CLOSES. Until this module landed, ``services/confirm/callback.py``
checked the ``signature`` field for PRESENCE and stored it. The local was named
``unverified_signature`` at every use site so that nobody could mistake the
field for a control, and the handler's docstring named the residual: the app
assertion proves the operator's APP is calling for this customer, and nothing
proved the HUMAN held the device and consented. Anything able to mint or steal
an app assertion -- a compromised app backend, a stolen assertion, a bug in
the issuer -- could approve that customer's pending challenges without the
phone ever being touched.

Now an approval must carry an Ed25519 signature, made by a key the operator
enrolled for that customer, over bytes built from the STORED CHALLENGE ROW.
`postern_core.auth.approval_signature` holds those bytes and the argument for
every field in them; `postern_core.auth.device_keys` holds where the key comes
from; this module is the call site and owns three decisions.

DECISION ONE: WHERE IT RUNS. ``_approve`` does, in order, the ZT-7 revocation
check, the signature-presence check, ``get_challenge``, the ownership check,
this, and then the conditional ``UPDATE``. Both boundaries are load-bearing:

- AFTER the ownership check, so that this refusal is not an existence oracle.
  ``services/confirm/callback.py`` answers a byte-identical 404 for "no such
  challenge" and "not yours" on purpose, because challenge ids travel back
  through the model's channel into a third-party AI vendor's chat history. A
  403 from here reaching a caller who does not own the challenge would answer
  "does this id exist" for any id they got hold of. Placed after it, the only
  callers who can distinguish these refusals are the ones the row already
  belongs to.
- BEFORE the conditional ``UPDATE``, so a failed verification cannot burn a
  challenge into a terminal state. That statement is what claims the challenge
  (``pending`` -> ``approved``), and the expiry retirement inside
  ``_refused_transition_response`` is a write too; neither must be reachable
  by a caller who cannot sign. A signature that does not verify leaves the row
  exactly ``pending``, so the customer's own phone can still approve it.

It cannot run earlier than ``get_challenge`` at all: the message is built from
the row, which is the property this whole control rests on.

DECISION TWO: WHAT AN UNCONFIGURED STORE DOES. Nothing here decides that,
because ``services/confirm/main.py``'s ``_device_key_store`` refuses to build
the app at all without one -- the same shape as its ``_assertion_verifier``
guard, and for the same reason that guard gives: "started with no
authentication" is not a mode worth supporting for convenience, it is the
audit finding. So the unconfigured case is a crash loop at startup and never a
request that got through. What remains reachable at request time is a store
that was WIRED and cannot ANSWER, which raises `DeviceKeyStoreUnavailable` and
is deliberately not caught here; see the fail-closed paragraph below.

DECISION THREE: THREE REFUSALS, NOT ONE. All three answer 403 and none of them
moves the challenge, but an operator reading ``audit_log`` must be able to
tell them apart, so each carries its own ``detail`` from
``services/confirm/audit.py``'s vocabulary:

``device_not_enrolled``
    The store answered, and this customer has no device enrolled. A support
    event -- the customer needs to enrol a phone -- and, in bulk, the shape of
    an enrolment pipeline that has stopped publishing.
``signature_malformed``
    The presented value is not a spelling of an Ed25519 signature at all. A
    client defect, not an attack: the app is sending the wrong encoding.
``signature_invalid``
    A well-formed signature over something other than this challenge, made by
    something other than an enrolled key. This is the one to alert on. It is
    what an attacker holding a valid app assertion produces.

The response BODY separates the first from the other two, and that is not an
oracle: the caller proved they are that customer before reaching this line, so
"you have no enrolled device" is a fact about themselves that their own app
needs in order to prompt for enrolment. The second and third share one body,
because the difference between them is the attacker's own encoding and tells
them nothing they did not already know.

FAIL CLOSED. `DeviceKeyStoreUnavailable` propagates, exactly as
`postern_core.auth.revocation`'s `RevocationStoreUnavailable` does one check
earlier: ``approve_challenge``'s ``except Exception`` writes a completion row
carrying the exception TYPE as its ``detail`` and re-raises, so the caller gets
a 500 and the challenge stays ``pending``. That is what keeps an enrolment
store outage distinguishable in the table from a customer with no enrolled
device -- ``detail = 'DeviceKeyStoreUnavailable'`` against ``detail =
'device_not_enrolled'`` -- where collapsing them would report an outage as
every customer having un-enrolled at once.

WHAT IS STILL NOT PROVED, stated here because the field now looks like proof
of user presence and is only proof of device possession: a verified signature
says the private half of an enrolled key signed exactly these bytes. It does
not say a human looked at the amount, and it does not say the phone was not
compromised. What closes THAT gap is the secure element and the device unlock
the operator's app requires before it signs -- both of which live on the
phone, outside anything this repository can attest.
"""

from __future__ import annotations

import logging

from postern_core.auth.approval_signature import (
    canonical_approval_message,
    decode_signature,
    verify_approval_signature,
)
from postern_core.auth.device_keys import DeviceKeyStoreBase
from postern_core.domain.masking import scrub_text
from postern_core.store.models import ChallengeRecord
from starlette.requests import Request
from starlette.responses import JSONResponse

from services.confirm.audit import (
    DETAIL_DEVICE_NOT_ENROLLED,
    DETAIL_SIGNATURE_INVALID,
    DETAIL_SIGNATURE_MALFORMED,
)

logger = logging.getLogger(__name__)

#: The error code for "this customer has no enrolled device". Distinct from
#: the one below because the caller's own app is what acts on it, by taking
#: the customer through enrolment; see decision three above for why that is
#: not a disclosure.
NOT_ENROLLED_ERROR = "device_not_enrolled"

#: The error code both signature failures return. One code for two details:
#: the audit row tells them apart, the caller does not need to.
INVALID_SIGNATURE_ERROR = "invalid_signature"  # noqa: S105 - an error code, not a credential


def device_key_store(request: Request) -> DeviceKeyStoreBase:
    """The enrolled-device store this app was assembled with.

    Typed rather than left as the ``Any`` that ``app.state`` hands back, so
    the call below is checked against the real interface -- the same reason
    ``services/confirm/revocation.py``'s ``revocation_store`` and
    ``services/confirm/callback.py``'s ``Database`` are annotated.

    NO ABSENT-STORE BRANCH, and that is the same decision
    ``services/confirm/revocation.py`` records: a route table that forgot to
    wire one hits Starlette's ``State.__getattr__`` and raises
    ``AttributeError``, which on this path becomes a completion row naming the
    exception type, a 500, and a challenge nobody touched. A branch here could
    only repeat that or return "no keys", and the second reads as a customer
    who has not enrolled.
    """
    store: DeviceKeyStoreBase = request.app.state.postern_device_key_store
    return store


async def signature_refusal(
    request: Request,
    *,
    record: ChallengeRecord,
    presented_signature: str,
) -> tuple[JSONResponse, str] | None:
    """``(response, detail)`` when the approval must be refused, or ``None``.

    ``None`` means an enrolled key signed exactly the bytes this challenge
    row canonicalises to, and the caller may proceed to claim it.

    Args:
        request: the approval request, read only for the app's key store.
        record: the STORED challenge row. Every byte verified comes from here.
        presented_signature: the one value the caller contributes.

    Raises:
        postern_core.auth.device_keys.DeviceKeyStoreUnavailable: the store
            could not answer. Never caught here; see the module docstring.
        postern_core.auth.approval_signature.UncanonicalChallengeError: the
            stored row cannot be serialised unambiguously, which is a defect
            in whatever wrote it.
    """
    # The store is asked for the ROW's customer, not the request's subject.
    # The ownership check one line up has already proved the two are equal, so
    # this is the same lookup either way -- but "every input to this check
    # comes from the stored row" is the property, and a reader should not have
    # to re-derive that the subject is safe to use here.
    keys = await device_key_store(request).keys_for(record.customer_ref)
    if not keys:
        logger.warning(
            "challenge approve: %s refused, no device is enrolled for its customer",
            record.challenge_id,
        )
        return (
            _refused(NOT_ENROLLED_ERROR, "no device is enrolled for this customer"),
            DETAIL_DEVICE_NOT_ENROLLED,
        )

    raw = decode_signature(presented_signature)
    if raw is None:
        logger.warning(
            "challenge approve: %s refused, the signature is not 86 base64url characters",
            record.challenge_id,
        )
        return (_refused(INVALID_SIGNATURE_ERROR, _REFUSAL), DETAIL_SIGNATURE_MALFORMED)

    message = canonical_approval_message(
        challenge_id=record.challenge_id,
        customer_ref=record.customer_ref,
        tool_name=record.tool_name,
        payload=record.payload,
        expires_at=record.expires_at,
    )
    verified = verify_approval_signature(keys=keys, message=message, signature=raw)
    if verified is None:
        # THE ROW TO ALERT ON. A well-formed signature that verifies against
        # none of this customer's enrolled devices is either a different
        # challenge's signature replayed, or a forgery attempt by something
        # holding a valid app assertion -- which is the exact adversary this
        # control was added for.
        logger.warning(
            "challenge approve: %s refused, the signature verifies against none of the "
            "%d device keys enrolled for its customer",
            record.challenge_id,
            len(keys),
        )
        return (_refused(INVALID_SIGNATURE_ERROR, _REFUSAL), DETAIL_SIGNATURE_INVALID)

    # WHICH DEVICE APPROVED, in the log and nowhere else. `challenges` has a
    # column for the caller-supplied `confirming_device` and none for the kid
    # that actually verified, and adding one is a migration this change does
    # not carry -- so the durable record of which enrolled key approved a
    # payment is this line. Scrubbed like every other value this service
    # writes out: a kid is operator-chosen, and `postern_core.domain.masking`
    # is what keeps a PAN-shaped one out of a log that outlives the incident.
    logger.info(
        "challenge approve: %s signature verified against enrolled device %s",
        record.challenge_id,
        scrub_text(verified.kid),
    )
    return None


#: One description for both signature refusals, so the two are one answer to
#: the caller and two rows in the table.
_REFUSAL = "the approval signature does not verify for this challenge"


def _refused(code: str, description: str) -> JSONResponse:
    """The 403 every refusal here returns.

    403 and not 401, matching ``services/confirm/revocation.py``'s
    ``revoked_response``: the caller authenticated correctly and is not
    permitted, which must not send an app into a re-authentication loop that
    cannot succeed. Not the 404 the ownership check uses, because by this
    line the caller has already been told the challenge is theirs.
    """
    return JSONResponse(status_code=403, content={"error": code, "error_description": description})

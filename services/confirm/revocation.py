"""ZT-7 on the write path: the one revocation question this service can ask.

WHAT THIS CLOSES. Until this module landed, ``grep -rc revocation
services/confirm/*.py`` returned zero on every file. An operator who revoked a
compromised session stopped every read on every replica within one call, and
stopped nothing here: a challenge already created could still be approved at
``POST /challenges/{challenge_id}/approve``, the approval callback still
minted a write JWT, and the backend write endpoint was still reached. **The
money still moved.** The RFC 8628 device-grant exchange at ``POST /token``
still minted and returned a read token for the same customer.

THE CHECK IS NOT PARITY WITH THE READ PATH, AND CANNOT BE. Do not assume it
is. `services/api/middleware/revocation.py` keys on three values off the
customer's validated access token -- ``jti``, ``sub`` and ``client_id``. This
service holds none of that pair's first or third member:

- **No AI-session ``jti``.** The only token on this path is a banking-app
  assertion minted by the operator's own app backend, a different issuer with
  a different token. Passing ITS ``jti`` into the session set would be a
  lookup in the wrong namespace -- a control that looks like a control, which
  is the defect the whole ZT-7 commit exists to remove.
- **No vendor ``client_id``.** `services/confirm/audit.py`'s `_client_id`
  already records why, for the audit column it fills: "there is no OAuth
  client at all. The caller is the operator's own banking app". Its
  ``client_id``/``azp``, when present, name that app, never the AI vendor.
- **Nothing recoverable from storage.** ``challenges`` has no ``jti`` column
  and no ``client_id`` column, and ``audit_log`` cannot be joined to a
  challenge by one either -- the read path returns a challenge id rather than
  taking one as an argument, so no row's ``arguments`` carries the key.

So this module asks `postern_core.auth.revocation`'s `is_customer_revoked`,
which matches any revocation naming the customer whatever the client. The
consequences, in the same words `postern_core.auth.revoke_cli` puts in front
of the operator:

- ``customer-client`` stops a challenge approval and a device-grant mint,
  through EVERY client and not only the one named.
- ``session`` stops reads only.
- ``kill-switch`` stops reads only.

**TO STOP THE WRITE PATH, NAME THE CUSTOMER.**

WHY THE CHECK IS NOT ASGI MIDDLEWARE, beside `AppAssertionMiddleware`. A
refusal here owes an ``audit_log`` row, for the reason
`services/api/middleware/revocation.py` gives for sitting INSIDE
``AuditMiddleware``: a refusal is exactly the event an operator wants a row
for. On this service the audit trail is not middleware -- `ApprovalAudit` is
constructed inside the handler out of the database, the two instants, the
correlation id, the verified subject, the assertion claims, the challenge id
AND the parsed JSON body. An ASGI middleware cannot reach that body without
draining ``receive``, which `services/confirm/auth.py` deliberately refuses to
do because it would leave nothing for the handler to read. So the check is a
call the handler makes, placed by hand, and each call site owes its placement.

WHERE EACH CALL SITE PUTS IT, AND WHY THERE:

``POST /challenges/{challenge_id}/approve``
    The FIRST statement of `services/confirm/callback.py`'s `_approve`,
    before the signature check and before the challenge is read. Before the
    read, so the refusal cannot become an existence oracle for a challenge id
    -- the same property the ownership check protects by answering 404. And
    necessarily before the conditional ``UPDATE`` that claims the challenge,
    so a revoked caller cannot burn somebody's challenge into a terminal
    state, and before `services/confirm/execute.py`'s `BackendWriteClient`
    mints anything.

``POST /approve``
    Immediately after the assertion's subject parses as a customer reference,
    before the device code is touched. Refusing here stops ``customer_ref``
    being written onto the device code at all, which is strictly better than
    refusing the mint that would read it back.

``POST /scan``
    The same place as ``POST /approve``: after the assertion's subject parses
    as a customer reference, before the body is read. Refusing here stops
    ``scanned_by`` being written onto the pairing, so a revoked customer never
    holds the claim that ``POST /approve`` requires.

``POST /token``
    Immediately before the read token is minted, keyed on the ``customer_ref``
    STORED on the device code -- written from a verified assertion at
    ``POST /approve`` and by nothing else. Never on ``DeviceCode.client_id``,
    which the browser supplies unauthenticated at ``POST /device_authorization``
    and can therefore set to anything; a kill switch enforced on it would be
    theatre.

FAIL CLOSED, in the shape each caller can use. `RevocationStoreUnavailable`
is never collapsed into "not revoked" -- that would un-revoke every entry at
the moment an operator most believes they have acted, and this service already
fails closed on an audit write it cannot make
(``dev-docs/decisions/0006-audit-write-failure.md``). The three assertion-backed
endpoints let it propagate: the approval path's own ``except Exception``
records a completion row whose ``detail`` is the exception type, per
`services/confirm/audit.py`'s convention, and the caller gets a 500 with the
challenge still ``pending``. ``POST /token`` answers 503 instead, because the
browser polling it is not the party that was revoked and an outage is not a
denial; `store_unavailable_response` below carries that argument.
"""

from __future__ import annotations

import logging

from postern_core.auth.revocation import RevocationStoreBase
from starlette.requests import Request
from starlette.responses import JSONResponse

logger = logging.getLogger(__name__)

#: The error code all three assertion-backed endpoints answer with. A distinct
#: value rather than the 404 the ownership check uses: the check runs before
#: any challenge is read, so this answer depends on nothing but the caller's
#: own revocation state and discloses nothing about a challenge, a device code
#: or another customer.
REVOKED_ERROR = "access_revoked"


def revocation_store(request: Request) -> RevocationStoreBase:
    """The shared store this app was assembled with.

    ``app.state.postern_revocation_store`` is the same attribute name
    `services/api/main.py` uses for the same object, so one grep finds both
    services' wiring. Typed rather than left as the ``Any`` that ``app.state``
    hands back, so `customer_revoked` below is checked against the real
    interface -- the same reason `services/confirm/callback.py` annotates its
    ``Database``.

    NO ABSENT-STORE BRANCH, and that is a decision rather than an omission. A
    route table that forgets to wire one hits Starlette's ``State.__getattr__``,
    which raises ``AttributeError`` for a name nothing set; on the approval
    path that becomes a completion row naming the exception type and a 500,
    and the challenge is untouched. Writing a branch here could only either
    repeat that or return "not revoked", and the second is how a control stops
    applying quietly. `services/confirm/auth.py`'s `verified_subject` makes the
    same argument for keeping its own unreachable 401.
    """
    store: RevocationStoreBase = request.app.state.postern_revocation_store
    return store


async def customer_revoked(request: Request, customer_ref: str) -> bool:
    """Whether any revocation names this customer.

    Raises `postern_core.auth.revocation.RevocationStoreUnavailable` when the
    store cannot answer. Every caller must let that refuse the request; see
    this module's docstring for the shape each one owes.
    """
    return await revocation_store(request).is_customer_revoked(customer_ref)


def revoked_response(description: str) -> JSONResponse:
    """The 403 all three assertion-backed endpoints return.

    Shared for the reason `services/confirm/auth.py`'s
    `unauthenticated_response` is shared: two call sites answering the same
    condition must not drift into two bodies. 403 rather than 401, matching
    `services/confirm/device_auth.py`'s existing ``invalid_subject``: the
    caller authenticated correctly and is not permitted, which is a different
    fact from failing to authenticate and must not send an app into a
    re-authentication loop that cannot succeed.
    """
    return JSONResponse(
        status_code=403,
        content={"error": REVOKED_ERROR, "error_description": description},
    )


def store_unavailable_response() -> JSONResponse:
    """The 503 ``POST /token`` answers when the revocation store cannot answer.

    NO TOKEN IS MINTED ON THIS PATH, which is the fail-closed half and is not
    in question. What this function decides is the SHAPE of the refusal, and
    the device grant makes that a real choice rather than a formality.

    Reusing RFC 8628 §3.5's ``access_denied`` would be fail-closed too, and
    was rejected: it is terminal, so a store outage would end every pairing in
    flight across the deployment -- an availability failure dressed as a
    security decision. The browser polling here holds no credential of its
    own and is not the party that was revoked; the right signal for it is one
    it can retry.

    ``temporarily_unavailable`` is RFC 6749 §4.1.2.1 vocabulary rather than a
    §5.2 token-endpoint code, and that is stated here rather than glossed: it
    is the honest name for the condition, no §5.2 code means "come back", and
    inventing a private one would be worse. Paired with 503 so a client that
    reads the status rather than the body also sees "retry".
    """
    return JSONResponse(
        status_code=503,
        content={
            "error": "temporarily_unavailable",
            "error_description": "authorization state cannot be checked; retry shortly",
        },
    )


def log_refusal(what: str) -> None:
    """One log line per refusal, naming the endpoint and nothing else.

    The customer reference is NOT logged, for the reason
    `services/api/middleware/revocation.py` gives at its own refusal:
    `postern_core.identity` warns that a ``sub`` minted by a compromised
    issuer can be PAN-, IBAN- or DNI-shaped, and this line reaches the
    operator's log whatever the issuer put there. On the read path the client
    id is what an operator greps for to confirm their revocation took effect;
    this service has none, so the endpoint is what is left, and the
    ``audit_log`` row is where the approval refusals are actually counted.
    """
    logger.warning("confirm: refused %s, the customer's access is revoked (ZT-7)", what)

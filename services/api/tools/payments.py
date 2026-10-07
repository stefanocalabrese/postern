"""`payments.create_payment` and `payments.get_payment_status`: the producer.

NOT A READ MODULE. Its tools write a `challenges` row, which no
`postern_core.modules.read.ReadContext` can do, and widening that context is
pinned against by `tests/test_module_seam.py`. They are built into the api's
composition instead: `register` below is called by `build_server` when it is
handed a `PaymentsRuntime`, which `create_app` builds only when
`POSTERN_PAYMENTS_ENABLED` is on.

WHAT IT DOES AND CANNOT DO. `create_payment` reads the payer account's balance
(for its currency) and the payee (for a display name) through the read facade,
builds the payload from those server-resolved values only, and inserts one
pending challenge, or returns the one this customer already has pending for
the same request. It cannot approve: that needs an enrolled device's signature
in `services/confirm`. It cannot execute: that needs the write key, which this
process does not hold.

ALWAYS CONSENT-GATED on `payments`, with the real `services/api/consent.py`
check, even where `build_server` gives the read tools its no-auth stand-in.
With no verified token the check refuses, so a server without customer auth
lists these tools to nobody.

EVERY REFUSAL IS A FIXED STRING raised as `ToolError`, which FastMCP 4.0.3
renders as an `isError` result whose one text block is exactly that string.
Any other exception reaches the client as "Error calling tool" followed by its
text, so nothing that could echo an input, a `ValidationError` included, is
let out as one.
"""

import logging
import re
import unicodedata
import uuid
from dataclasses import dataclass
from decimal import Decimal

from fastmcp import FastMCP
from fastmcp.exceptions import ToolError
from mcp.types import ToolAnnotations
from postern_core.domain.masking import FreeText
from postern_core.domain.models import Ref
from postern_core.domain.money import Money
from postern_core.facade import accounts as accounts_facade
from postern_core.facade import payments as payments_facade
from postern_core.facade.client import BackendError
from postern_core.facade.protocol import BackendReader
from postern_core.identity import CustomerResolver, TokenClaimsProvider
from postern_core.modules.read import ToolHandler
from postern_core.payments import (
    CREATE_PAYMENT_TOOL,
    PAYMENT_STATUS_TOOL,
    PAYMENT_TIER,
    request_fingerprint,
)
from postern_core.store import challenges as store
from postern_core.store.engine import Database
from pydantic import TypeAdapter, ValidationError
from sqlalchemy.exc import SQLAlchemyError

from services.api.consent import consent_for

logger = logging.getLogger(__name__)

#: The consent domain the producer's tools are gated on.
CONSENT_DOMAIN = "payments"

#: The fixed refusals (spec section 9). Constants so tests assert the exact
#: strings a client sees.
ACCOUNT_NOT_FOUND = "account not found"
PAYEE_NOT_FOUND = "payee not found"
AMOUNT_INVALID = "amount must be a positive decimal with at most 4 decimal places"
REFERENCE_TOO_LONG = "reference is limited to 140 characters"
REFERENCE_NOT_PRINTABLE = "reference may contain only printable characters"
CHALLENGE_NOT_FOUND = "challenge not found"
NOT_RECORDED = "the payment could not be recorded"
#: One text for a stored row the status tool cannot answer from (a payload that
#: is not an object, or lacks a text amount, currency or payee name) and for a
#: database failure on the status read. Both mean "could not be read".
CHALLENGE_UNREADABLE = "the payment status could not be read"

#: The longest `reference` accepted, counted on what the agent sent.
MAX_REFERENCE_LENGTH = 140

#: The widest `client_id` or `jti` stored. Both columns are `String(128)`. A
#: longer claim is stored as NULL rather than truncated: a truncated value
#: would later match the wrong revocation, and NULL matches none.
MAX_CLAIM_LENGTH = 128

#: Annotations for both tools (spec sections 6.1 and 6.2). Neither is
#: read-only: one inserts a challenge, the other may expire one.
ANNOTATIONS = ToolAnnotations(
    read_only_hint=False,
    destructive_hint=False,
    idempotent_hint=True,
    open_world_hint=False,
)

_AMOUNT = re.compile(r"[0-9]{1,15}(?:\.[0-9]{1,4})?")
#: Not a `Ref`: the producer's ids are 32 hex characters, and other callers
#: store ids such as `chal_int_001`.
_CHALLENGE_ID = re.compile(r"[A-Za-z0-9_-]{1,36}")
#: Payload keys the status answer cannot do without. `reference` is optional.
_REQUIRED_PAYLOAD_KEYS = ("amount", "currency", "payee_name")
_FREE_TEXT: TypeAdapter[str] = TypeAdapter(FreeText)


@dataclass(frozen=True)
class PaymentsRuntime:
    """What the producer holds beyond a read tool's resolver and backend.

    Attributes:
        db: The process's one `Database`. The challenge transaction uses its
            application pool, and the consent check reads through it.
        claims: The verified token's `client_id` and `jti`, stored on the row
            for later revocation matching and never used as a gate.
    """

    db: Database
    claims: TokenClaimsProvider


def canonical_amount(value: Decimal) -> str:
    """`value` with at least two and at most four decimals, and no exponent.

    So "340.5", "340.50" and "340.5000" are one string, and therefore one
    fingerprint. The caller has already matched `_AMOUNT`, so `value` has at
    most fifteen integer digits and four decimals, inside the default
    context's 28 digits of precision.
    """
    normalized = value.normalize()
    exponent = normalized.as_tuple().exponent
    if isinstance(exponent, int) and exponent > -2:
        normalized = normalized.quantize(Decimal("0.01"))
    return format(normalized, "f")


def _amount(raw: str) -> str:
    """The canonical amount, or the fixed refusal. Needs no backend read."""
    if not _AMOUNT.fullmatch(raw):
        raise ToolError(AMOUNT_INVALID)
    value = Decimal(raw)
    if value <= 0:
        raise ToolError(AMOUNT_INVALID)
    return canonical_amount(value)


def _check_money(canonical: str, currency: str) -> None:
    """`Money` is built for its own checks (finite, at most four decimals, a
    three-letter currency) and then dropped: the payload holds strings only,
    because `canonical_approval_message` refuses a float.
    """
    try:
        Money(amount=Decimal(canonical), currency=currency)
    except ValidationError:
        raise ToolError(AMOUNT_INVALID) from None


def _is_unprintable(char: str) -> bool:
    """A control, format, surrogate, private-use or unassigned character, or a
    line or paragraph separator (U+2028, U+2029).

    Plain emoji are category So and pass. A zero-width joiner (U+200D) is Cf
    and is refused, so an emoji ZWJ sequence is refused as a whole: a joiner is
    also what hides text between two visible characters.
    """
    category = unicodedata.category(char)
    return category.startswith("C") or category in ("Zl", "Zp")


def _reference(raw: str | None) -> str | None:
    """`raw` scrubbed by `FreeText`, after the printable and length checks on
    what was sent.

    The reference is the only agent-controlled text in the approval display, so
    a newline or an escape sequence must not reach it: it could fake a line
    the customer reads as the server's. The stored text can differ from the
    input, because `FreeText` redacts PAN- and IBAN-shaped runs and masks long
    alphanumeric runs. The stored text is what the customer is later shown.
    """
    if raw is None:
        return None
    if any(_is_unprintable(char) for char in raw):
        raise ToolError(REFERENCE_NOT_PRINTABLE)
    if len(raw) > MAX_REFERENCE_LENGTH:
        raise ToolError(REFERENCE_TOO_LONG)
    return _FREE_TEXT.validate_python(raw)


def _claim(value: str | None) -> str | None:
    if value is None or len(value) > MAX_CLAIM_LENGTH:
        return None
    return value


def _display(value: object) -> str | None:
    """A stored payload value as the status tool shows it: text only, and
    scrubbed again, because a row this tool reads may have been written by a
    caller other than `create_payment`."""
    if not isinstance(value, str):
        return None
    return _FREE_TEXT.validate_python(value)


def build_create_payment(
    resolver: CustomerResolver, backend: BackendReader, runtime: PaymentsRuntime
) -> ToolHandler:
    async def create_payment(
        from_account_ref: Ref,
        payee_ref: Ref,
        amount: str,
        reference: str | None = None,
    ) -> dict[str, str]:
        """Propose a payment; the customer approves it in their banking app.

        This moves no money. It records a proposal and returns a `challenge_id`.
        `from_account_ref` comes from `accounts.list`; `payee_ref` is a payee the
        customer already saved. `amount` is a decimal string such as "340.50" in
        the payer account's currency. `reference` is optional, at most 140
        characters. Relay `human_summary`, then check `payments.get_payment_status`.
        """
        # Cheap checks first: a malformed amount or reference costs no backend
        # read. Only the currency check needs the balance.
        canonical = _amount(amount)
        stored_reference = _reference(reference)
        customer = resolver()
        try:
            balance = await accounts_facade.get_balance(backend, customer, from_account_ref)
        except BackendError as exc:
            if exc.status == 404:
                raise ToolError(ACCOUNT_NOT_FOUND) from None
            raise
        try:
            payee = await payments_facade.get_payee(backend, customer, payee_ref)
        except BackendError as exc:
            if exc.status == 404:
                raise ToolError(PAYEE_NOT_FOUND) from None
            raise
        currency = balance.amount.currency
        _check_money(canonical, currency)
        payload: dict[str, str] = {
            "from_account_ref": from_account_ref,
            "payee_ref": payee.payee_ref,
            "payee_name": payee.display_name,
            "amount": canonical,
            "currency": currency,
        }
        if stored_reference is not None:
            payload["reference"] = stored_reference
        fingerprint = request_fingerprint(
            customer_ref=customer.value, tool_name=CREATE_PAYMENT_TOOL, payload=payload
        )
        claims = runtime.claims()
        try:
            async with runtime.db.sessionmaker() as session:
                record = await store.create_pending_challenge_once(
                    session,
                    challenge_id=uuid.uuid4().hex,
                    customer_ref=customer.value,
                    tool_name=CREATE_PAYMENT_TOOL,
                    payload=payload,
                    tier=PAYMENT_TIER,
                    request_fingerprint=fingerprint,
                    client_id=_claim(claims.client_id),
                    session_jti=_claim(claims.jti),
                )
                await session.commit()
        except (SQLAlchemyError, OSError) as exc:
            # The type and nothing else: a DBAPIError's text carries the bound
            # parameters, which are this customer's payload.
            logger.error(
                "%s could not record its challenge: %s", CREATE_PAYMENT_TOOL, type(exc).__name__
            )
            raise ToolError(NOT_RECORDED) from None
        if record is None:
            raise ToolError(NOT_RECORDED)
        return {
            "challenge_id": record.challenge_id,
            "status": record.status,
            "expires_at": record.expires_at.isoformat(),
            "human_summary": (
                f"Approve {currency} {canonical} to {payee.display_name} in your banking app."
            ),
        }

    return create_payment


def build_get_payment_status(resolver: CustomerResolver, runtime: PaymentsRuntime) -> ToolHandler:
    async def get_payment_status(challenge_id: str) -> dict[str, str | None]:
        """Status of a payment proposed with `payments.create_payment`.

        `pending` until the customer acts in their banking app, then `approved`
        or `executed`, or `expired` once the deadline passes. `approved` does NOT
        mean the bank refused it, and does not mean it was executed: the customer
        approved, and either the bank refused it, or the outcome is unknown, or
        the bank accepted it and the record failed. Do not propose the same
        payment again unless the customer explicitly asks. Tell the customer the
        outcome is unconfirmed and to check their account or ask their bank.
        """
        customer = resolver()
        if not _CHALLENGE_ID.fullmatch(challenge_id):
            raise ToolError(CHALLENGE_NOT_FOUND)
        try:
            async with runtime.db.sessionmaker() as session:
                record = await store.get_challenge(session, challenge_id)
                # Missing, another customer's, or not a payment: one path and
                # one message, so the answer confirms nothing about which.
                if (
                    record is None
                    or record.customer_ref != customer.value
                    or record.tool_name != CREATE_PAYMENT_TOOL
                ):
                    raise ToolError(CHALLENGE_NOT_FOUND)
                if record.status == "pending":
                    # The approval callback's own conditional transition, with
                    # the deadline decided by the database clock (decision 0022
                    # records this one api-side UPDATE).
                    expired = await store.update_challenge_status(
                        session,
                        challenge_id,
                        status="expired",
                        expected_status="pending",
                        expiry="expired",
                    )
                    if expired is None:
                        # A race that makes the conditional UPDATE match
                        # nothing re-reads the row, so the answer is never a
                        # stale `pending`.
                        # Not past its deadline, or another transaction moved
                        # it first: the committed row is the answer.
                        refreshed = await store.get_challenge(session, challenge_id, refresh=True)
                        record = refreshed if refreshed is not None else record
                    else:
                        record = expired
                    await session.commit()
        except (SQLAlchemyError, OSError) as exc:
            logger.error(
                "%s could not read its challenge: %s", PAYMENT_STATUS_TOOL, type(exc).__name__
            )
            raise ToolError(CHALLENGE_UNREADABLE) from None
        payload = record.payload
        # The row is this customer's own payment, but any caller may have
        # written it: fail closed on a shape this tool did not produce. The log
        # names the tool only, never the payload or the customer.
        if not isinstance(payload, dict) or not all(
            isinstance(payload.get(key), str) for key in _REQUIRED_PAYLOAD_KEYS
        ):
            logger.error("%s found an unreadable stored payment", PAYMENT_STATUS_TOOL)
            raise ToolError(CHALLENGE_UNREADABLE)
        return {
            "challenge_id": record.challenge_id,
            "status": record.status,
            "expires_at": record.expires_at.isoformat(),
            "amount": _display(payload.get("amount")),
            "currency": _display(payload.get("currency")),
            "payee_name": _display(payload.get("payee_name")),
            "reference": _display(payload.get("reference")),
        }

    return get_payment_status


def register(
    server: FastMCP,
    resolver: CustomerResolver,
    backend: BackendReader,
    runtime: PaymentsRuntime,
) -> None:
    """Register the producer's tools, each behind `consent_for("payments", ...)`.

    One check object for every producer tool, for the reason
    `services/api/server.py`'s `build_server` gives for a domain's read tools.
    Never the no-auth stand-in: a server without customer auth refuses these
    tools to every caller, which is what the spec asks of it.
    """
    check = consent_for(CONSENT_DOMAIN, runtime.db)
    server.tool(
        build_create_payment(resolver, backend, runtime),
        name=CREATE_PAYMENT_TOOL,
        annotations=ANNOTATIONS,
        auth=check,
    )
    server.tool(
        build_get_payment_status(resolver, runtime),
        name=PAYMENT_STATUS_TOOL,
        annotations=ANNOTATIONS,
        auth=check,
    )

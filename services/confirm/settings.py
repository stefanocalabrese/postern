"""Settings for the write path and device authorization flow.

There is deliberately no read key field here, and no write key field in
services/api/settings.py. The asymmetry is the control, and it is greppable.

Device authorization (§7.3 of the handoff) adds:
- ``device_verification_uri`` -- base URI of the browser's pairing page.
  ``verification_uri_complete`` is this plus ``?d=`` and the pairing's display
  handle.
- ``device_app_link_uri`` -- the operator's universal-link / app-link base.
  The QR on the pairing page encodes this plus ``user_code`` and a rotation
  token, so a phone camera hands it to the bank app. It must be ``https`` with
  a hostname, and that host must differ from ``device_verification_uri``'s;
  ``from_env`` refuses to start otherwise. ``from_env`` also refuses a
  ``device_verification_uri`` whose path is not ``/verify``, or that carries a
  query or a fragment.
- ``device_code_ttl_seconds`` — lifetime of a device code (default 900 = 15
  min), refused below ``MIN_DEVICE_CODE_TTL_SECONDS`` because the Redis store
  cannot represent a shorter one (bug B1; that constant carries the working).
- ``device_poll_interval_seconds`` — minimum seconds between token polls (default 5).

The confirm service holds NO READ KEY. Until the layer-1 session token it
held one, as a recorded exception, because ``POST /token`` minted the
browser a read token with it -- a layer-2 token the accounts backend accepts,
which handoff §7.1 keeps apart from layer 1. The device grant now issues a
session token signed by a third key, SESSION (the ``session_*`` fields
below), which signs nothing else and is published at ``/session/jwks.json``.
So no process holds READ and WRITE together: ``services/api`` holds READ,
this service holds WRITE and SESSION, and the device grant's read-key
exception is gone. ``tests/test_confirm_service.py`` pins the field list.

Approval callback (§6.3, §8.3) adds:
- ``backend_base_url`` — base URL for backend write endpoints (payments.svc,
  cards.svc). The callback POSTs to these after marking a challenge approved.
- ``database_url`` — Postgres connection for the challenges table.

Inbound authentication (audit findings C-01, C-02) adds the three
``app_assertion_*`` fields. They configure the ``JWTVerifier`` that
``services/confirm/auth.py`` checks the banking app's bearer assertion with,
and all three are REQUIRED: ``create_confirm_app`` refuses to build an app
without them. ``services/api`` may legitimately run with ``auth=None`` for
local development, and this service may not — the read path serves masked
balances to a process that cannot mint a write token, and this one holds the
write key and approves money movement. Making the unauthenticated
configuration unrepresentable is cheaper than remembering not to deploy it.

The approval signature check (2026-09-24) adds a fourth required field,
``device_keys_path``, for the same reason and with the same consequence:
``create_confirm_app`` refuses to build without it, because a confirm service
that cannot verify an approval signature is the finding
``services/confirm/device_signature.py`` exists to close, and a default would
make reaching that state a typo rather than a decision. It names a JSON
document of enrolled device public keys whose format
``postern_core.auth.device_keys`` owns.

``app_assertion_audience`` has no default on purpose. A default would be a
value an operator never typed, and the value that matters here is the one
that must NOT collide with ``services/api/settings.py``'s ``audience``
(``"postern"``, the customer tokens third-party AI clients present). If the
two matched, a token good enough to read a balance would be good enough to
approve a payment. Nothing in this process can check that — the other service
is a different deployment with a different environment, and ``.importlinter``
forbids reading its settings — so the requirement is stated in
``services/confirm/auth.py``'s docstring and enforced only by an operator.
"""

import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

from postern_core.auth.device_codes import (
    MIN_DEVICE_CODE_TTL_SECONDS as _MIN_DEVICE_CODE_TTL_SECONDS,
)
from postern_core.auth.refresh_sessions import SESSION_ABSOLUTE_LIFETIME
from postern_core.auth.resource_uri import is_normal_https_resource, is_plain_ascii_uri_text
from postern_core.auth.revocation import (
    CUSTOMER_REVOKED_AT_TTL_SECONDS,
    REVOKED_AT_MARGIN_SECONDS,
)
from postern_core.auth.vault import VaultSettings, vault_from_env
from postern_core.config import bool_from_env, float_from_env, int_from_env

from services.confirm.auth import (
    DEFAULT_ASSERTION_MAX_LIFETIME_SECONDS,
    MAX_ASSERTION_MAX_LIFETIME_SECONDS,
)

logger = logging.getLogger(__name__)

#: The scope string ``POST /device_authorization`` substitutes when the caller
#: sends none. It lives here rather than inline in
#: `services/confirm/device_auth.py` because ``max_scopes_length`` below is
#: floored at its LENGTH, and a floor derived from a literal in another module
#: is a floor that rots the first time someone edits the literal.
DEFAULT_DEVICE_SCOPES = "accounts:read transactions:read cards:read"

#: The shortest ``POSTERN_MAX_SCOPES_LENGTH`` that leaves the endpoint able to
#: serve its own default, which is 42 characters as of 2026-09-25.
#:
#: DERIVED, NOT PICKED, and it is the one length in this file that can be. A
#: request to ``POST /device_authorization`` that carries no ``scopes`` gets
#: `DEFAULT_DEVICE_SCOPES` substituted for it, and the length check runs
#: AFTER the substitution -- so a ceiling below this length refuses the
#: request an ordinary browser sends, with ``invalid_scope``, naming a scope
#: string the caller never wrote. The endpoint cannot serve its own default,
#: which is not a tighter control but an unreachable one.
#:
#: WHAT IT DELIBERATELY DOES NOT CLAIM: that 42 is a usable ceiling. It is
#: not; 512 is the default and the comment on ``max_scopes_length`` carries
#: why. This bounds what is REPRESENTABLE, in the same sense
#: `MIN_DEVICE_CODE_TTL_SECONDS` below uses the word, and nothing more.
MIN_SCOPES_LENGTH = len(DEFAULT_DEVICE_SCOPES)


def _positive_int(name: str, default: int) -> int:
    """Read a positive integer from the environment, or refuse to start.

    WHY THIS RAISES RATHER THAN FALLING BACK TO THE DEFAULT. A rate limit an
    operator meant to raise and typoed is worse than one they never touched:
    silently keeping the default means the variable they set to fix an
    outage did nothing, and they find out from the same alert they were
    already looking at. The failure has to land at boot.

    ``0`` and negatives are refused rather than treated as "unlimited" or
    "refuse everything". Both readings are defensible, which is exactly why
    neither should be guessed from a bare number: an operator who wants no
    limit on a path says so by raising it, and there is deliberately no value
    that turns the control off.

    This is the same posture as ``RiskMiddleware.__init__`` refusing a
    negative ``trusted_proxy_hops`` and ``create_confirm_app`` refusing
    incomplete assertion settings: a misconfiguration that would quietly
    change a control's meaning fails when the app is assembled.

    The offending value is echoed because it is an operator's own
    environment, not caller input -- the opposite of the rule
    `services/confirm/device_auth.py` follows for a malformed customer
    reference, which is attacker-reachable and never logged.

    THE BODY MOVED ON 2026-09-25 AND THE MESSAGES DID NOT. Everything above
    is now `postern_core/config.py`'s `int_from_env`, which the rest of this
    module's numbers and both of `services/api/settings.py`'s families also
    read through -- the alternative was a second validation style for the
    variables this function never covered. ``minimum=1`` is what makes that
    helper say "a positive integer" rather than "an integer of at least 1",
    so the two strings this raises are unchanged to the byte and
    ``tests/test_settings_bounds.py::TestPositiveIntMessagesAreUnchanged``
    pins both against the literals that were here.
    """
    return int_from_env(
        name,
        default,
        minimum=1,
        because=("It is a per-minute request count; there is no value that disables the limit."),
    )


_ASSERTION_MAX_LIFETIME_BECAUSE = (
    f"It is how many seconds ahead an app assertion's exp may sit, from 1 to "
    f"{MAX_ASSERTION_MAX_LIFETIME_SECONDS}; the assertion authorises /scan, /approve "
    "and the challenge approval callback, and there is no value that lets it never expire."
)


def _assertion_max_lifetime(value: int) -> int:
    """Refuse a maximum assertion lifetime above ``MAX_ASSERTION_MAX_LIFETIME_SECONDS``.

    ``int_from_env`` states a floor and no ceiling, so ``from_env`` reads the
    variable through it with ``minimum=1`` and passes the result here for the
    upper bound. The message names the variable and echoes the value, the way
    that helper's refusals do.
    """
    if value > MAX_ASSERTION_MAX_LIFETIME_SECONDS:
        raise ValueError(
            f"POSTERN_CONFIRM_ASSERTION_MAX_LIFETIME_SECONDS must be at most "
            f"{MAX_ASSERTION_MAX_LIFETIME_SECONDS}, got {value}. "
            f"{_ASSERTION_MAX_LIFETIME_BECAUSE}"
        )
    return value


#: The most a successful pairing scan may wait for the network enricher.
#:
#: A CEILING, which ``float_from_env`` cannot state, so ``from_env`` refuses a
#: larger value itself through ``_pairing_enricher_timeout``. It exists for
#: two reasons: the budget is added to a successful scan's latency while the
#: customer holds their phone, and it widens the window between a committed
#: claim and its ``audit_log`` row.
MAX_PAIRING_ENRICHER_TIMEOUT_SECONDS = 1.0

_PAIRING_ENRICHER_TIMEOUT_BECAUSE = (
    "It bounds how long a successful pairing scan waits for the network enricher; "
    "at zero no lookup could ever complete."
)


def _pairing_enricher_timeout(value: float) -> float:
    """Refuse an enricher budget above ``MAX_PAIRING_ENRICHER_TIMEOUT_SECONDS``.

    ``float_from_env`` states a floor and no ceiling, so ``from_env`` reads the
    variable through it with ``minimum=0, exclusive=True`` and passes the
    result here for the upper bound, the shape ``_assertion_max_lifetime``
    already has.
    """
    if value > MAX_PAIRING_ENRICHER_TIMEOUT_SECONDS:
        raise ValueError(
            f"POSTERN_CONFIRM_PAIRING_ENRICHER_TIMEOUT_SECONDS must be at most "
            f"{MAX_PAIRING_ENRICHER_TIMEOUT_SECONDS}, got {value}. "
            f"{_PAIRING_ENRICHER_TIMEOUT_BECAUSE}"
        )
    return value


#: Re-exported from `postern_core.auth.device_codes`, which is where the
#: floor's derivation now lives, because the arithmetic that creates it lives
#: there too (``_set_code``) and because a SECOND variable reaches that same
#: arithmetic. ``POSTERN_REDIS_DEVICE_CODE_TTL``, read by
#: `RedisDeviceCodeStore`'s constructor, sets the lifetime of the same object
#: ``POSTERN_DEVICE_CODE_TTL_SECONDS`` does. Two literals would let an
#: operator set one safely and the other not, so there is one number and both
#: read it.
MIN_DEVICE_CODE_TTL_SECONDS = _MIN_DEVICE_CODE_TTL_SECONDS

#: The longest ``POSTERN_DEVICE_CODE_TTL_SECONDS`` the customer revocation
#: stamp can cover: `postern_core.auth.revocation`'s
#: ``CUSTOMER_REVOKED_AT_TTL_SECONDS`` less the refresh family's lifetime and
#: ``REVOKED_AT_MARGIN_SECONDS``, which is 900 today. An approved code must not
#: outlive the stamp it is compared with at ``POST /token``, and the stamp's
#: writer cannot read this service's settings, so the ceiling lands here.
MAX_DEVICE_CODE_TTL_SECONDS = (
    CUSTOMER_REVOKED_AT_TTL_SECONDS
    - int(SESSION_ABSOLUTE_LIFETIME.total_seconds())
    - REVOKED_AT_MARGIN_SECONDS
)


def _device_code_ttl(name: str, default: int) -> int:
    """Read a device-code lifetime from the environment, or refuse to start.

    Deliberately the same shape as `_positive_int` above -- read, refuse,
    echo, name the variable -- rather than a second validation style, and
    for the same stated reason: a value an operator typed and got wrong must
    fail when the app is assembled, not silently revert to a default they
    did not choose. What differs is only the bound, because the quantity is
    a duration rather than a per-minute count, and `MIN_DEVICE_CODE_TTL_SECONDS`
    carries its derivation.

    A CEILING SINCE THE LAYER-1 SESSION TOKEN, `MAX_DEVICE_CODE_TTL_SECONDS`.
    Until then a lifetime that was too LONG was left to the operator, as a
    risk RFC 8628 sets no bound on. It is now unrepresentable in a narrower
    sense: an approved code longer-lived than the customer revocation stamp
    could be redeemed after a revoke-and-restore that the stamp no longer
    remembers. A value that is too SHORT is refused for the older reason: it
    produces a service that cannot complete a pairing at all, and on the
    Redis backend it does so silently.

    The offending value is echoed for the reason `_positive_int` gives: this
    is an operator's own environment, not caller input.
    """
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    try:
        value = int(raw)
    except ValueError:
        raise ValueError(
            f"{name} must be an integer of at least {MIN_DEVICE_CODE_TTL_SECONDS} seconds, "
            f"got {raw!r}. It is the lifetime of a device code, and a shorter one cannot "
            "outlive the browser's poll interval or the user's approval on their phone."
        ) from None
    if value < MIN_DEVICE_CODE_TTL_SECONDS:
        raise ValueError(
            f"{name} must be at least {MIN_DEVICE_CODE_TTL_SECONDS} seconds, got {value}. "
            "It is the lifetime of a device code, and a shorter one cannot outlive the "
            "browser's poll interval or the user's approval on their phone; at 1 second "
            "the Redis store's truncation discards the code without storing it at all."
        )
    if value > MAX_DEVICE_CODE_TTL_SECONDS:
        raise ValueError(
            f"{name} must be at most {MAX_DEVICE_CODE_TTL_SECONDS} seconds, got {value}. "
            "An approved device code must not outlive the customer revocation stamp "
            f"({CUSTOMER_REVOKED_AT_TTL_SECONDS} seconds) that POST /token compares its "
            "approval with, less the one-hour session family and a "
            f"{REVOKED_AT_MARGIN_SECONDS}-second margin."
        )
    return value


def _app_link_uri(page_uri: str) -> str:
    """Read ``POSTERN_DEVICE_APP_LINK_URI``, refusing one a phone cannot open as an app link.

    Empty or unset is the local placeholder default. Four refusals, each a
    ``ValueError`` naming the variable:

    - A ``?`` or a ``#`` anywhere in the value. The pairing QR appends
      ``?user_code=...&qr=...`` to it, so after a fragment the parameters land
      where no server or app link handler receives them, and after a query they
      merge into the operator's own query string. The characters are tested
      rather than ``urlsplit``'s query and fragment, which are empty for a bare
      trailing ``?`` or ``#``, as `_verification_uri` does.
    - A scheme other than ``https``. Apple universal links and Android
      verified app links are ``https`` only; an ``http`` link opens a browser.
    - No hostname, which is what ``urlsplit`` makes of a bare ``/pair`` and of
      ``app.bank.test/pair`` with its scheme missing. There is no host to
      publish the associated-domains or asset-links file on.
    - A host shared with the page. A phone camera handed a URL on the page's
      host opens the browser page, not the bank app, so the pairing could
      never reach ``POST /scan``. Hostnames are compared case-folded; a port
      does not make a different host.

    The offending values are echoed, as `_device_code_ttl` does, because they
    are an operator's own environment.

    The checks live in `_check_app_link_uri`, which `ConfirmSettings.__post_init__`
    calls as well, so a value built in code is held to the same rules.
    """
    link = os.environ.get("POSTERN_DEVICE_APP_LINK_URI") or "https://app.postern.internal/pair"
    return _check_app_link_uri(link, page_uri)


def _check_app_link_uri(link: str, page_uri: str) -> str:
    """Return ``link`` if it is a usable app link beside ``page_uri``, else raise ``ValueError``.

    The rules are `_app_link_uri`'s; the messages name the environment
    variable, which is what an operator reading a startup failure acts on.
    """
    if "?" in link or "#" in link:
        raise ValueError(
            f"POSTERN_DEVICE_APP_LINK_URI ({link!r}) must not contain '?' or '#'. "
            "The pairing QR appends ?user_code=...&qr=... to it: after a fragment the "
            "parameters reach no server or app, and after a query they merge into it."
        )
    parts = urlsplit(link)
    if parts.scheme != "https" or not parts.hostname:
        raise ValueError(
            f"POSTERN_DEVICE_APP_LINK_URI ({link!r}) must be an https URL with a hostname. "
            "Universal links and verified app links are https only, and the pairing QR "
            "encodes this value for a phone camera to hand to the bank app."
        )
    page_host = (urlsplit(page_uri).hostname or "").casefold()
    if parts.hostname.casefold() == page_host:
        raise ValueError(
            f"POSTERN_DEVICE_APP_LINK_URI ({link!r}) must not share a host with "
            f"POSTERN_DEVICE_VERIFICATION_URI ({page_uri!r}). "
            "A phone camera handed a URL on the page's host opens the browser page "
            "instead of the bank app, so a pairing could never be scanned."
        )
    return link


#: The path the pairing page is served on, in ``services/confirm/verify_page.py``.
VERIFY_PAGE_PATH = "/verify"


def _verification_uri(page_uri: str) -> str:
    """Return ``page_uri``, refusing one ``?d=`` cannot be appended to.

    ``verification_uri_complete`` is this value plus ``?d=`` and a display
    handle. Two refusals, each a ``ValueError`` naming the variable:

    - A path other than ``/verify``. This service serves the page there and
      nowhere else, so any other path hands the user a 404 at the first step
      of pairing. ``/verify/`` does not match the route either.
    - A ``?`` or a ``#`` anywhere in the value. A query makes ``?a=1?d=``, and
      a fragment carries ``?d=`` inside it, where the server never sees the
      handle. The characters are tested rather than ``urlsplit``'s query and
      fragment, which are empty for a bare trailing ``?`` or ``#``.

    The value itself comes from ``from_env``, which reads the variable, and
    from ``ConfirmSettings.__post_init__``, which passes the field.
    """
    if urlsplit(page_uri).path != VERIFY_PAGE_PATH:
        raise ValueError(
            f"POSTERN_DEVICE_VERIFICATION_URI ({page_uri!r}) must have the path "
            f"{VERIFY_PAGE_PATH!r}, the route the pairing page is served on. "
            "verification_uri_complete is this value plus ?d=, so any other path "
            "sends the user to a 404."
        )
    if "?" in page_uri or "#" in page_uri:
        raise ValueError(
            f"POSTERN_DEVICE_VERIFICATION_URI ({page_uri!r}) must carry no query and "
            "no fragment. verification_uri_complete is this value plus ?d=, which a "
            "query would turn into ?a=1?d= and a fragment would hide from the server."
        )
    return page_uri


@dataclass(frozen=True)
class ConfirmSettings:
    write_key_pem_path: str | None = None
    write_key_kid: str = "write-1"
    write_token_issuer: str = "https://mcp-write.internal"  # noqa: S105
    # VAULT TRANSIT. `vault` is the same six values `services/api/settings.py`
    # reads, from the same `vault_from_env`, because there is one Vault. This
    # service names two transit keys, the write key here and the session key
    # below, and names no read key. What keeps the split real under Vault is
    # not this dataclass: it is the policy on the Vault token each SERVICE
    # holds. The api service's token has `update` on `transit/sign/<read key>`
    # and nothing on the write or session key, and this service's token has
    # nothing on the read key -- measured against Vault 1.20.4 in
    # `tests/test_vault_live.py`.
    vault: VaultSettings | None = None
    vault_write_key_name: str = "postern-write"
    # Device authorization (§7.3): where the user goes to approve pairing.
    device_verification_uri: str = "https://auth.postern.internal/verify"
    # The base of the app link the pairing QR encodes. A placeholder host for
    # local work, like the field above; a deployment owes its own, with the
    # Apple associated-domains and Android asset-links files that make a
    # camera open the bank app. `_app_link_uri` refuses one on the page's host.
    device_app_link_uri: str = "https://app.postern.internal/pair"
    # Floored at `MIN_DEVICE_CODE_TTL_SECONDS` when it comes from the
    # environment, which is where that constant's working lives. The field
    # default stays 900 and is the only lifetime here derived for real use.
    device_code_ttl_seconds: int = 900
    device_poll_interval_seconds: int = 5
    # Approval callback (§6.3, §8.3): backend write endpoints + challenges DB.
    backend_base_url: str = "https://backend.internal"  # noqa: S105
    # repr=False: the URL carries the database password (see services/api/settings.py).
    database_url: str = field(
        default="postgresql+asyncpg://postern:postern@localhost:5432/postern", repr=False
    )
    database_connect_timeout_seconds: float = 2.0
    database_command_timeout_seconds: float = 3.0
    database_pool_timeout_seconds: float = 1.0
    # LOWER THAN THE READ PATH'S, and the asymmetry is the point. Both
    # services hold connections against one database, so a connection this
    # one keeps is one an API replica cannot have, and the two paths are
    # driven by different things: `services/api` serves whatever an LLM
    # decides to call, at a rate nobody here controls, while one row through
    # this service is one person tapping approve on a phone after a push
    # notification. Ten per replica is 10 simultaneous approvals inside a
    # database operation, where each operation is one indexed statement.
    #
    # An approval costs FOUR checkouts and holds ONE at a time (claim, entry
    # audit row, executed transition, completion audit row), and none of them
    # spans the backend write, so a slow payments service cannot drain this
    # pool -- `tests/test_pool_sizing.py` measures both halves of that.
    #
    # RAISE IT if approvals here are refused: the symptom is a 500 whose log
    # carries `sqlalchemy.exc.TimeoutError` and "QueuePool limit of size ...
    # reached", about 2 seconds after the request arrived, since the audit
    # row that records the failure waits the same pool_timeout again.
    # `dev-docs/decisions/0013-connection-pool-ceiling.md` holds the
    # arithmetic to redo before raising it.
    database_pool_size: int = 5
    database_max_overflow: int = 5
    # THE RESERVE, and on this service it is narrower than on the read path by
    # one deliberate omission. `postern_core.store.engine`'s `Database` builds
    # a second engine of this many connections and no overflow;
    # `postern_core.store.audit`'s `append_with_reserve` reaches it only when
    # the pool above raises `sqlalchemy.exc.TimeoutError`.
    #
    # WHAT IT RECORDS HERE. `services/confirm/audit.py`'s COMPLETION writes --
    # `ApprovalAudit._completion` and `PairingAudit._write` -- and not
    # `ApprovalAudit._write_entry_row`. That asymmetry is the whole design and
    # `tests/test_audit_reserve.py`'s
    # `TestTheEntryRowIsDeliberatelyNotOnTheReserve` carries the argument: the
    # entry row is the last statement before a backend WRITE endpoint is
    # reached, and the `approved -> executed` transition that follows the money
    # moving is not an audit write, so no reserve can cover it. Putting the
    # entry row on the reserve would carry a request across the money boundary
    # on a connection that cannot carry it to the end -- the write succeeds and
    # the transition is then refused by the very pool the reserve was standing
    # in for, stranding the challenge in `approved` with the money gone. So the
    # entry row keeps the pool's answer, the backend is not reached, and the
    # refusal is what the reserve records.
    #
    # WHAT THAT BUYS, and it is the worst case rather than the common one: a
    # `raised` row for every approval a saturated replica refuses, and a row
    # for the case the money DID move and the transition then failed, which is
    # the one state `dev-docs/decisions/0013-connection-pool-ceiling.md`
    # already names as this service's reason to keep headroom. Before the
    # reserve that row was lost exactly when it mattered most.
    #
    # It is a CEILING, not a standing cost: `QueuePool` opens on demand and
    # this engine is only ever asked after a refused checkout, so an
    # unsaturated replica holds none of it. Budget it anyway -- the moment one
    # replica needs it is the moment they all do.
    database_audit_reserve_size: int = 1
    # Inbound app assertion (C-01, C-02). All three required; see the module
    # docstring for why there is no audience default and why this service,
    # unlike `services/api`, has no no-auth path at all.
    app_assertion_jwks_uri: str | None = None
    app_assertion_issuer: str | None = None
    app_assertion_audience: str | None = None
    # How far ahead of now an app assertion's `exp` may sit, in seconds.
    # `services/confirm/auth.py`'s `_lifetime_refusal` enforces it, plus
    # `ASSERTION_CLOCK_SKEW_SECONDS`, and refuses an assertion with no `exp`.
    #
    # 300 BY DEFAULT. The assertion is minted by the app backend for one
    # request from the phone, so a lifetime only needs to cover mint, network
    # and a retry; five minutes is that with room. It is also the window in
    # which an assertion captured from the phone or a log authorises
    # `/scan`, `/approve` and the challenge callback for its `sub`.
    #
    # 3600 AS A CEILING, refused above at startup. An hour is the lifetime
    # OAuth deployments commonly give an access token, and past it an
    # assertion outlives any session the app could be said to hold, so the
    # bound stops meaning "short-lived" and becomes only "not forever".
    app_assertion_max_lifetime_seconds: int = DEFAULT_ASSERTION_MAX_LIFETIME_SECONDS
    # Enrolled device public keys, the input to the approval signature check
    # (`services/confirm/device_signature.py`). A path rather than a
    # connection string, and a field here rather than an environment variable
    # read inside a factory the way `create_revocation_store` and
    # `create_device_code_store` read `POSTERN_REDIS_URL`: this is key
    # material the operator renders, so it follows `write_key_pem_path`
    # above, and `postern_core.auth.device_keys` records
    # at length why enrolment data must not share the cache's variable.
    #
    # REQUIRED, with no default, exactly like the three assertion fields:
    # `create_confirm_app` refuses to build without it. A default would be a
    # path the operator never typed, and the failure mode of getting it wrong
    # is a service that cannot approve anything -- which is fail-closed, and
    # is still an outage an operator must meet at startup rather than at the
    # first payment.
    device_keys_path: str | None = None
    # The ceiling `services/confirm/body_limit.py` enforces on every request
    # body this service will read into memory. Measured before it existed:
    # `POST /device_authorization` read 9,999,989 bytes and answered 200 with
    # no credential presented at all.
    #
    # 64 KiB, and the interval it sits in is derived even though the point in
    # it is not:
    #
    # - THE FLOOR IS 8,192, `postern_core.store.audit`'s `MAX_ARGUMENTS_BYTES`
    #   -- the most of a body that can ever reach `audit_log.arguments` from
    #   this service. A limit below it would make the bound `579dfd7` put on
    #   that column unreachable from any request, which is not a tighter
    #   control but a dead one.
    # - THE CEILING THAT MATTERS is what a legitimate body actually is. The
    #   whole approval tree measures under 300 bytes; `/token` carries
    #   `grant_type` plus a 43-character device code; `/approve` carries one
    #   short code. 64 KiB is ~220x the largest of those and 8x the floor,
    #   which left room for the per-customer device signature this path owed
    #   when the bound was chosen. That signature landed on 2026-09-24 and
    #   costs 86 characters (`postern_core.auth.approval_signature`'s
    #   `SIGNATURE_BYTES`, base64url-encoded), so the room was never needed.
    #
    # A DELIBERATELY DIFFERENT ENVIRONMENT VARIABLE FROM `services/api`'s
    # `POSTERN_MAX_BODY_BYTES`, which is 1 MiB. Sharing the name would mean an
    # operator raising the READ path's ceiling -- which that service's own
    # comment invites, "a deployment that later adds a tool with a genuinely
    # larger request body (a bulk import, say) must raise this deliberately"
    # -- silently raising the WRITE path's by the same factor, in a repository
    # whose `docker-compose.yml` runs both services from one file. The two
    # bound different things: a JSON-RPC tool-call envelope there, an approval
    # body here. An operator who needs this one wider must say so separately,
    # with `POSTERN_CONFIRM_MAX_BODY_BYTES`.
    max_body_bytes: int = 65_536
    # How many proxies in front of this service append to ``X-Forwarded-For``.
    # `services/confirm/rate_limit.py` keys its counters on the address this
    # selects, and `postern_core.net`'s `client_ip` holds what the number
    # means and why the default of zero trusts the header for nothing.
    #
    # A DELIBERATELY SEPARATE VARIABLE FROM `services/api`'s
    # ``POSTERN_TRUSTED_PROXY_HOPS``, for the reason
    # ``POSTERN_CONFIRM_MAX_BODY_BYTES`` above is separate: these are two
    # deployables that this repository's ``docker-compose.yml`` happens to
    # run from one file, and nothing guarantees they sit behind the same
    # number of proxies. `.importlinter` forbids this module from reading the
    # other service's settings to find out, so an operator sets each.
    trusted_proxy_hops: int = 0
    # How long, in seconds, a successful ``POST /scan`` waits for the pairing
    # network enricher's two lookups before recording ``"unknown"``. Above 0
    # and at most `MAX_PAIRING_ENRICHER_TIMEOUT_SECONDS`. 250 ms is a choice,
    # not a measurement: no provider ships here to measure.
    pairing_enricher_timeout_seconds: float = 0.25
    # The ceiling on how many device codes the store will hold, enforced by
    # `postern_core.auth.device_codes`. Its ``DEFAULT_MAX_DEVICE_CODES``
    # carries the measurement and the derivation of the number.
    max_device_codes: int = 10_000
    # Ceilings on the two fields ``POST /device_authorization`` copies out of
    # an unauthenticated request body and stores for the code's whole life.
    #
    # THESE ARE WHAT MAKE THE STORE CAP MEAN A NUMBER OF BYTES. A cap counts
    # entries, so without a bound on what one entry can cost it bounds
    # nothing: measured on 2026-09-24, a device code holding a realistic
    # ``scopes`` string costs 1,633 bytes and one padded to the 64 KiB body
    # limit costs 65,560, so 40x of the standing cost was one caller-supplied
    # string. `services/confirm/body_limit.py` does not bound it either --
    # it counts wire bytes, and 24,000 bytes of JSON list parse to 67,252
    # bytes of Python objects, so the body limit is not a bound on what the
    # store holds at all.
    #
    # 512 and 256 characters. The default scope string this service issues is
    # 42 characters ("accounts:read transactions:read cards:read"), and the
    # four domains the architecture names could not plausibly exceed 200;
    # OAuth client identifiers are UUIDs or short labels. Both are ~12x the
    # largest legitimate value, which is the same shape of margin
    # ``max_body_bytes`` was chosen with.
    max_scopes_length: int = 512
    max_client_id_length: int = 256
    # How many requests one client address bucket may make to each path per
    # minute. `services/confirm/rate_limit.py`'s ``DEFAULT_LIMITS`` carries
    # the working behind each default and these five values reproduce it
    # exactly; what they add is a way to change one without a code change.
    #
    # WHICH WAY TO SET THESE, which is worth more than the knob itself. The
    # limit is keyed on a client ADDRESS BUCKET, so the question is always
    # "how many customers sit behind one address in this deployment?", and
    # there are two cases where the answer is "a great many":
    #
    # - CARRIER-GRADE NAT, on the public paths. A mobile carrier can put
    #   thousands of subscribers behind one IPv4 address, so a browser-facing
    #   limit low enough to bite an attacker holding a handful of addresses is
    #   low enough to hurt a real NAT pool. The defaults are set on the side
    #   that does not break customers, and the store cap rather than this is
    #   what bounds memory.
    # - THE APP BACKEND, on the three assertion-authenticated paths, and this is
    #   the one that will hurt if it is wrong. ``rate_limit_approve``,
    #   ``rate_limit_challenge_approve`` and ``rate_limit_scan`` default to
    #   60/min per bucket, which is right if the operator's banking app calls
    #   this service FROM THE CUSTOMER'S PHONE, because then the addresses are
    #   as diverse as the customers. If instead the app's BACKEND calls on the phone's behalf,
    #   every approval in the bank arrives from a handful of egress addresses
    #   and 60/min becomes a bank-wide ceiling on payment approvals. An
    #   operator in that shape must raise these three, and the fact that it is
    #   an environment variable rather than a release is the whole point:
    #   discovering it at 3am costs a restart, not a deploy.
    #
    # The honest limit of all five: a per-address bound is the wrong UNIT for
    # an authenticated path, where the meaningful one is per customer. That
    # gap is now closed by a SECOND limiter rather than by re-keying these --
    # the three ``customer_rate_limit_*`` fields below configure it -- and these
    # five keep their numbers because that second limiter runs after
    # authentication and needs this one in front of it as the backstop.
    rate_limit_device_authorization: int = 60
    rate_limit_token: int = 300
    rate_limit_approve: int = 60
    rate_limit_challenge_approve: int = 60
    rate_limit_default: int = 60
    # How many requests ONE CUSTOMER may make to each assertion-authenticated
    # path per minute. `services/confirm/customer_rate_limit.py`'s
    # ``DEFAULT_CUSTOMER_LIMITS`` carries the working behind each default and
    # these values reproduce it exactly.
    #
    # WHICH WAY TO SET THESE, and it is the opposite question from the five
    # above. Those ask "how many customers sit behind one address?"; these ask
    # "how fast can one person tap approve?", and the answer does not vary
    # with the deployment's network shape at all. All three paths are one tap
    # on a phone per unit of work, so an operator who finds these tight should look
    # first at whether their app retries on a timeout, because a client-side
    # retry loop is the only legitimate traffic that reaches ten a minute.
    #
    # THE DEFAULT SHARES ``POSTERN_REDIS_URL`` WITH THE OTHER THREE STORES.
    # Unset, the counters are per replica, which for a per-customer ceiling
    # means R replicas admit R times these numbers -- see
    # `services/confirm/customer_rate_limit.py`'s
    # ``InMemoryCustomerRateLimitStore``. A multi-replica deployment must set
    # it, and the revocation list, session store and device code store all
    # want it set for their own reasons already.
    customer_rate_limit_approve: int = 10
    customer_rate_limit_challenge_approve: int = 10
    # THE QR PAGE AND ``POST /scan``, added 2026-09-30: six more per-address
    # counts and one more per-customer count, each reproducing its entry in
    # `services/confirm/rate_limit.py`'s ``DEFAULT_LIMITS`` or
    # `services/confirm/customer_rate_limit.py`'s ``DEFAULT_CUSTOMER_LIMITS``
    # exactly, where the working behind each number lives. The five public
    # routes are the browser's, so the carrier-grade NAT reasoning above
    # applies to them; ``/scan`` is the app's, so the app-backend reasoning
    # applies to it.
    rate_limit_scan: int = 60
    rate_limit_verify: int = 60
    rate_limit_verify_qr: int = 300
    rate_limit_verify_state: int = 300
    rate_limit_verify_js: int = 60
    rate_limit_verify_css: int = 60
    customer_rate_limit_scan: int = 10
    # THE LAYER-1 SESSION TOKEN (dev-docs/device-grant-session-token-spec.md
    # section 2). A THIRD signing key, which signs the access token
    # ``POST /token`` issues and nothing else, published at
    # ``/session/jwks.json``. The kid, PEM path and transit key name follow
    # the write key's three fields above and reach the same
    # `choose_key_source`, so the Vault, PEM and generated branches and the
    # refusal of both at once are inherited rather than restated.
    session_key_pem_path: str | None = None
    session_key_kid: str = "session-1"
    vault_session_key_name: str = "postern-session"
    # The ``iss`` of every access token: this service's public issuer URL.
    # `check_session_token_settings` refuses one that is not ``https`` with a
    # host, or that equals another issuer this process knows.
    session_token_issuer: str = "https://auth.postern.internal"  # noqa: S105
    # The ``aud`` of every access token: the MCP server's resource URI, which
    # must equal ``services/api``'s ``POSTERN_AUDIENCE``. The DEFAULT IS A
    # LOCAL-ONLY VALUE that `check_session_token_settings` refuses unless
    # ``allow_non_uri_audience`` is set, because RFC 8707 section 2 requires
    # an absolute URI.
    session_token_audience: str = "postern"  # noqa: S105
    # Two development flags, both off by default, because a default is what a
    # hand-built settings object gets and these defaults are the ones a
    # deployment may run. `ConfirmSettings.for_testing` sets both.
    allow_non_uri_audience: bool = False
    allow_process_local_sessions: bool = False
    # The ceiling on live refresh-token families: ``max_device_codes`` times
    # the lifetime ratio (3,600 s against 900 s), so a store in which every
    # live device code were exchanged as fast as codes can exist still fits.
    max_refresh_sessions: int = 40_000
    # Per-address requests a minute to ``/session/jwks.json``, fetched by
    # every ``services/api`` worker process on a cache miss.
    rate_limit_session_jwks: int = 300

    def __post_init__(self) -> None:
        # The pairing URIs are checked however the settings are built, because
        # `verify_page.py`'s app link always appends ``?`` to the base, so a
        # base carrying ``?`` or ``#`` yields a link no app handler receives.
        # `from_env` runs the same validators and so passes through here twice.
        _verification_uri(self.device_verification_uri)
        _check_app_link_uri(self.device_app_link_uri, self.device_verification_uri)

    @classmethod
    def from_env(cls) -> "ConfirmSettings":
        device_verification_uri = _verification_uri(
            os.environ.get(
                "POSTERN_DEVICE_VERIFICATION_URI",
                "https://auth.postern.internal/verify",
            )
        )
        return cls(
            write_key_pem_path=os.environ.get("POSTERN_WRITE_KEY_PEM_PATH") or None,
            write_key_kid=os.environ.get("POSTERN_WRITE_KEY_KID", "write-1"),
            vault=vault_from_env(),
            vault_write_key_name=os.environ.get(
                "POSTERN_VAULT_WRITE_KEY_NAME", "postern-write"
            ).strip()
            or "postern-write",
            write_token_issuer=os.environ.get(
                "POSTERN_WRITE_TOKEN_ISSUER", "https://mcp-write.internal"
            ),
            device_verification_uri=device_verification_uri,
            device_app_link_uri=_app_link_uri(device_verification_uri),
            device_code_ttl_seconds=_device_code_ttl("POSTERN_DEVICE_CODE_TTL_SECONDS", 900),
            # FLOOR OF ONE SECOND, and no ceiling from this line -- though one
            # is derivable and is deliberately not taken here. At zero or below
            # `services/confirm/device_auth.py`'s ``elapsed <
            # settings.device_poll_interval_seconds`` is never true, so the RFC
            # 8628 poll throttle never fires and there is no value that turns
            # the control off, which is `_positive_int`'s posture above. The
            # ceiling that exists is a RELATION rather than a number: an
            # interval at or above ``device_code_ttl_seconds`` expires the code
            # before the browser is permitted to poll even once, which is the
            # second of the three bounds `MIN_DEVICE_CODE_TTL_SECONDS` is built
            # from. Enforcing that pair is a cross-field check this function
            # does not make, and the hazard is real: 1000 against the default
            # 900 parses today and pairs nothing.
            device_poll_interval_seconds=int_from_env(
                "POSTERN_DEVICE_POLL_INTERVAL_SECONDS",
                5,
                minimum=1,
                because=(
                    "It is the minimum seconds between /token polls (RFC 8628 §3.2); at "
                    "zero the slow_down throttle never fires, and there is no value that "
                    "disables it."
                ),
            ),
            backend_base_url=os.environ.get("POSTERN_BACKEND_BASE_URL", "https://backend.internal"),
            database_url=os.environ.get(
                "POSTERN_DATABASE_URL",
                "postgresql+asyncpg://postern:postern@localhost:5432/postern",
            ),
            # The same three bounds, the same three reasons and the same
            # asymmetry as `services/api/settings.py` -- these are one variable
            # each, read by both services, so they must not disagree about what
            # they accept. That module's docstring carries the measurement
            # behind "connect and command refuse zero, pool does not".
            database_connect_timeout_seconds=float_from_env(
                "POSTERN_DATABASE_CONNECT_TIMEOUT_SECONDS",
                2.0,
                minimum=0,
                exclusive=True,
                because=(
                    "It becomes asyncpg's connect(timeout=); at zero every connection to "
                    "a reachable Postgres raises TimeoutError, so no challenge row can be "
                    "read or written."
                ),
            ),
            database_command_timeout_seconds=float_from_env(
                "POSTERN_DATABASE_COMMAND_TIMEOUT_SECONDS",
                3.0,
                minimum=0,
                exclusive=True,
                because=(
                    "It becomes asyncpg's command_timeout, which asyncpg itself refuses "
                    "at or below zero -- but not until the first connect, with a message "
                    "naming the parameter and not this variable."
                ),
            ),
            database_pool_timeout_seconds=float_from_env(
                "POSTERN_DATABASE_POOL_TIMEOUT_SECONDS",
                1.0,
                minimum=0,
                because=(
                    "It becomes SQLAlchemy's pool_timeout; zero sheds instead of queueing "
                    "when the pool is saturated, and a negative value does the same thing "
                    "while reading as 'wait forever'."
                ),
            ),
            # PREFIXED, WHERE THE THREE DEADLINES ABOVE ARE NOT, and the rule
            # behind that split is already in this file: a number both
            # services want the same answer to is one variable
            # (POSTERN_DATABASE_COMMAND_TIMEOUT_SECONDS), and a number they
            # want different answers to gets the POSTERN_CONFIRM_ prefix, the
            # way POSTERN_CONFIRM_MAX_BODY_BYTES sits beside
            # POSTERN_MAX_BODY_BYTES at 64 KiB against 1 MiB. The ceiling is
            # the second kind: this service defaults to 5 + 5 and the read
            # path to 5 + 10. A shared name would have meant an operator
            # raising the read path's burst silently raised this one too, in
            # a deployment where both containers read one env file.
            database_pool_size=int_from_env(
                "POSTERN_CONFIRM_DATABASE_POOL_SIZE",
                5,
                minimum=1,
                because=(
                    "It becomes SQLAlchemy's pool_size, the connections this replica keeps "
                    "open, and replicas x (pool_size + max_overflow) has to clear the "
                    "database's max_connections. Zero is not a small pool but an unbounded "
                    "one: measured, an engine at pool_size=0 held 25 connections at once."
                ),
            ),
            database_max_overflow=int_from_env(
                "POSTERN_CONFIRM_DATABASE_MAX_OVERFLOW",
                5,
                minimum=0,
                because=(
                    "It becomes SQLAlchemy's max_overflow, the connections this replica may "
                    "open above pool_size and close again on return. Zero is a legitimate "
                    "setting and means no burst; -1 is the off switch, and an engine set to "
                    "it held 25 connections at once against a ceiling that read as one."
                ),
            ),
            # A FLOOR OF ONE, matching the read path's: there is no value that
            # turns the reserve off. Reaching zero from the environment would
            # mean a deployment choosing to lose the row for every approval a
            # saturated replica refuses -- including the one that records money
            # having moved with the executed transition refused, which is the
            # single row in this table an investigator most needs. An operator
            # short of connections raises max_connections or lowers
            # POSTERN_CONFIRM_DATABASE_POOL_SIZE; both leave the record intact.
            #
            # ITS OWN NAME, with the POSTERN_CONFIRM_ prefix the ceiling pair
            # above carries and for the identical reason: one env file read by
            # both containers must not let an operator move the read path's
            # reserve and this one together without meaning to.
            database_audit_reserve_size=int_from_env(
                "POSTERN_CONFIRM_DATABASE_AUDIT_RESERVE_SIZE",
                1,
                minimum=1,
                because=(
                    "It is the connections held back so an approval's completion row can "
                    "still be written when this service's pool is at its ceiling, and it "
                    "adds to the replicas x ceiling total that has to clear the database's "
                    "max_connections. There is no value that turns it off: at zero a "
                    "saturated replica refuses approvals and records nothing about having "
                    "refused them."
                ),
            ),
            app_assertion_jwks_uri=os.environ.get("POSTERN_APP_ASSERTION_JWKS_URI") or None,
            app_assertion_issuer=os.environ.get("POSTERN_APP_ASSERTION_ISSUER") or None,
            app_assertion_audience=os.environ.get("POSTERN_APP_ASSERTION_AUDIENCE") or None,
            app_assertion_max_lifetime_seconds=_assertion_max_lifetime(
                int_from_env(
                    "POSTERN_CONFIRM_ASSERTION_MAX_LIFETIME_SECONDS",
                    DEFAULT_ASSERTION_MAX_LIFETIME_SECONDS,
                    minimum=1,
                    because=_ASSERTION_MAX_LIFETIME_BECAUSE,
                )
            ),
            device_keys_path=os.environ.get("POSTERN_DEVICE_KEYS_PATH") or None,
            # A FLOOR OF ONE BYTE, and deliberately NOT the 8,192 the comment
            # on ``max_body_bytes`` derives. That derivation is of the bottom
            # of the USEFUL interval -- below `postern_core/store/audit.py`'s
            # `MAX_ARGUMENTS_BYTES` the cap on that column stops being
            # reachable -- and a service configured under it still serves every
            # legitimate body, all of which measure under 300 bytes. At zero it
            # does not: `services/confirm/body_limit.py` refuses any request
            # carrying a body at all with 413, which is /device_authorization,
            # /token and /approve, so the whole flow is dead. Only the second
            # one is unrepresentable, and only it is refused.
            max_body_bytes=int_from_env(
                "POSTERN_CONFIRM_MAX_BODY_BYTES",
                65_536,
                minimum=1,
                because=(
                    "It is the ceiling on a request body this service will read; at zero "
                    "every request carrying a body is refused 413, which is every route "
                    "on the device grant and the approval callback."
                ),
            ),
            trusted_proxy_hops=int_from_env(
                "POSTERN_CONFIRM_TRUSTED_PROXY_HOPS",
                0,
                minimum=0,
                because=(
                    "It is how many proxies in front of this process append to "
                    "X-Forwarded-For; zero is the default and already means 'trust the "
                    "header for nothing', so there is nothing below it left to express."
                ),
            ),
            pairing_enricher_timeout_seconds=_pairing_enricher_timeout(
                float_from_env(
                    "POSTERN_CONFIRM_PAIRING_ENRICHER_TIMEOUT_SECONDS",
                    0.25,
                    minimum=0,
                    exclusive=True,
                    because=_PAIRING_ENRICHER_TIMEOUT_BECAUSE,
                )
            ),
            # FLOOR OF ONE. Measured on 2026-09-25: at zero
            # ``InMemoryDeviceCodeStore``'s ``len(self._codes) >=
            # self._max_codes`` is true on an EMPTY store, so the first
            # /device_authorization of the process raises ``DeviceCodeStoreFull
            # ('device code store holds 0 codes, at its cap of 0')`` and no
            # pairing can ever start. Negatives do the same.
            max_device_codes=int_from_env(
                "POSTERN_MAX_DEVICE_CODES",
                10_000,
                minimum=1,
                because=(
                    "It is how many device codes the store will hold; at zero the cap is "
                    "met by an empty store and every pairing is refused."
                ),
            ),
            # FLOOR OF `MIN_SCOPES_LENGTH`, which is the only length here that
            # is derived rather than asserted -- that constant carries why.
            max_scopes_length=int_from_env(
                "POSTERN_MAX_SCOPES_LENGTH",
                512,
                minimum=MIN_SCOPES_LENGTH,
                because=(
                    "It is the ceiling on the `scopes` string; below the length of the "
                    "default this endpoint substitutes for a caller that sends none, "
                    "every ordinary request is refused invalid_scope."
                ),
            ),
            # FLOOR OF ONE, asserted rather than derived, and that is the
            # honest state of it: `client_id` is required and non-empty, so at
            # zero ``len(client_id) > 0`` refuses every request that reaches
            # the check. Nothing in this repository measures how long a real
            # OAuth client identifier is -- the comment on
            # ``max_client_id_length`` reasons from UUIDs and short labels, not
            # from a measurement -- so no larger floor would be more than a
            # number someone liked. A ceiling is unnecessary: `max_body_bytes`
            # already bounds this value on the wire.
            max_client_id_length=int_from_env(
                "POSTERN_MAX_CLIENT_ID_LENGTH",
                256,
                minimum=1,
                because=(
                    "It is the ceiling on the `client_id` string, which is required and "
                    "non-empty; at zero every /device_authorization is refused."
                ),
            ),
            rate_limit_device_authorization=_positive_int(
                "POSTERN_CONFIRM_RATE_LIMIT_DEVICE_AUTHORIZATION", 60
            ),
            rate_limit_token=_positive_int("POSTERN_CONFIRM_RATE_LIMIT_TOKEN", 300),
            rate_limit_approve=_positive_int("POSTERN_CONFIRM_RATE_LIMIT_APPROVE", 60),
            rate_limit_challenge_approve=_positive_int(
                "POSTERN_CONFIRM_RATE_LIMIT_CHALLENGE_APPROVE", 60
            ),
            rate_limit_default=_positive_int("POSTERN_CONFIRM_RATE_LIMIT_DEFAULT", 60),
            # Through the SAME `_positive_int` as the five above, so the two
            # families raise identical messages for identical mistakes and
            # there is no fourth numeric-parsing style in this tree. The
            # helper's `because` -- "It is a per-minute request count; there
            # is no value that disables the limit" -- is true of these
            # verbatim.
            customer_rate_limit_approve=_positive_int(
                "POSTERN_CONFIRM_CUSTOMER_RATE_LIMIT_APPROVE", 10
            ),
            customer_rate_limit_challenge_approve=_positive_int(
                "POSTERN_CONFIRM_CUSTOMER_RATE_LIMIT_CHALLENGE_APPROVE", 10
            ),
            rate_limit_scan=_positive_int("POSTERN_CONFIRM_RATE_LIMIT_SCAN", 60),
            rate_limit_verify=_positive_int("POSTERN_CONFIRM_RATE_LIMIT_VERIFY", 60),
            rate_limit_verify_qr=_positive_int("POSTERN_CONFIRM_RATE_LIMIT_VERIFY_QR", 300),
            rate_limit_verify_state=_positive_int("POSTERN_CONFIRM_RATE_LIMIT_VERIFY_STATE", 300),
            rate_limit_verify_js=_positive_int("POSTERN_CONFIRM_RATE_LIMIT_VERIFY_JS", 60),
            rate_limit_verify_css=_positive_int("POSTERN_CONFIRM_RATE_LIMIT_VERIFY_CSS", 60),
            customer_rate_limit_scan=_positive_int("POSTERN_CONFIRM_CUSTOMER_RATE_LIMIT_SCAN", 10),
            session_key_pem_path=os.environ.get("POSTERN_SESSION_KEY_PEM_PATH") or None,
            session_key_kid=os.environ.get("POSTERN_SESSION_KEY_KID", "session-1"),
            vault_session_key_name=os.environ.get(
                "POSTERN_VAULT_SESSION_KEY_NAME", "postern-session"
            ).strip()
            or "postern-session",
            session_token_issuer=os.environ.get(
                "POSTERN_SESSION_TOKEN_ISSUER", "https://auth.postern.internal"
            ),
            session_token_audience=os.environ.get("POSTERN_SESSION_TOKEN_AUDIENCE", "postern"),
            allow_non_uri_audience=bool_from_env(
                "POSTERN_ALLOW_NON_URI_AUDIENCE",
                False,
                because=(
                    "It lets a local stack run with an access-token audience that is not "
                    "an absolute https URI, which RFC 8707 section 2 requires."
                ),
            ),
            allow_process_local_sessions=bool_from_env(
                "POSTERN_ALLOW_PROCESS_LOCAL_SESSIONS",
                False,
                because=(
                    "It lets the device grant run without POSTERN_REDIS_URL, so refresh "
                    "families and recalls live in this process and nowhere else."
                ),
            ),
            max_refresh_sessions=int_from_env(
                "POSTERN_MAX_REFRESH_SESSIONS",
                40_000,
                minimum=1,
                because=(
                    "It is how many refresh-token families the store will hold; at zero "
                    "the cap is met by an empty store and every exchange is refused."
                ),
            ),
            rate_limit_session_jwks=_positive_int("POSTERN_CONFIRM_RATE_LIMIT_SESSION_JWKS", 300),
        )

    @classmethod
    def for_testing(cls) -> "ConfirmSettings":
        """Settings that build an app which authenticates NOBODY successfully.

        ``device_keys_path`` is deliberately left ``None`` here, which means
        these settings alone do not build an app at all: a test that wants one
        passes ``device_key_store=no_enrolled_devices()`` to
        ``create_confirm_app``, the same way it passes ``assertion_verifier=``.
        Both halves of "this fixture can approve nothing" are then written at
        the call site rather than hidden in a default, which is the whole
        reason `postern_core.auth.device_keys`'s ``no_enrolled_devices`` has a
        name.

        The three ``app_assertion_*`` values point at
        ``app.postern-local-dev.invalid``. RFC 2606 reserves ``.invalid``, so
        the name cannot resolve and no request leaves the machine, and the
        ``postern-local-dev.invalid`` suffix is the placeholder host this
        repository already uses (``docker-compose.yml``), which is what keeps
        ``tests/test_zt8_no_hardcoded_external_endpoints.py`` passing without
        widening that gate's allowlist for a test fixture.

        ``JWTVerifier`` does no network at construction — it fetches a JWKS
        lazily, inside ``load_access_token`` — so the app builds, every route
        that needs an assertion refuses every token, and that is the correct
        default for a fixture.

        ``database_url`` IS THE ONE VALUE READ FROM THE ENVIRONMENT HERE, and
        the one dependency this helper cannot fake. It became necessary on
        2026-09-26, when ``POST /approve`` started writing an ``audit_log``
        row: 31 tests across ``tests/test_device_grant.py``,
        ``tests/test_confirm_rate_limit.py``,
        ``tests/test_confirm_customer_rate_limit.py`` and
        ``tests/test_confirm_auth.py`` drive that endpoint through
        ``create_confirm_app`` and then answered 500 against the field default
        of ``localhost:5432``, which no test container listens on. Several of
        those call sites are inside test methods with no fixture to thread a
        URL through, so the honest fix is here rather than four autouse
        fixtures that patch this classmethod.

        ``POSTERN_DATABASE_URL`` and not a new variable, because that is the
        name ``from_env`` above already reads for this field and the name
        ``tests/conftest.py``'s session-scoped ``pg_url`` already exports when
        it starts its Postgres. The fallback is this dataclass's own field
        default, so an environment that sets nothing gets exactly what it got
        before.

        This is deliberately NOT a generated key pair. Generating RSA material
        per call would put a key generation in the path of every test that
        merely wants an app object (``tests/test_ephemeral_key_warning.py``
        builds one three times over), and it would make the default fixture
        one that CAN authenticate somebody, which is the wrong direction for a
        service whose finding was that it authenticated everybody. A test that
        needs a working assertion passes ``assertion_verifier=`` to
        ``create_confirm_app`` with a ``JWTVerifier(public_key=...)`` over an
        ``RSAKeyPair.generate()``, mirroring ``auth_override`` on the api side.
        """
        return cls(
            app_assertion_jwks_uri=("https://app.postern-local-dev.invalid/.well-known/jwks.json"),
            app_assertion_issuer="https://app.postern-local-dev.invalid",
            app_assertion_audience="postern-confirm",
            database_url=os.environ.get("POSTERN_DATABASE_URL") or cls.database_url,
            # Both development flags, and only here: the audience default,
            # ``postern``, is not a URI, and a test process has no shared Redis.
            allow_non_uri_audience=True,
            allow_process_local_sessions=True,
        )


def _refuse_shared_session_key(settings: ConfirmSettings) -> None:
    """Refuse a SESSION key NAMED as the write key.

    THE CHEAP EARLY ERROR, and not the whole control: it compares names, kids
    and resolved paths, so a copied PEM, a hardlink or a case-different path
    passes it. ``services.confirm.session_token.refuse_shared_key_material``
    compares the key material itself, once both sources are built.

    The keys are kept apart by what each one is trusted for, and that holds
    only while they are different keys: a session token signed by the write
    key would verify wherever write tokens do. Nothing else enforces it, so a
    configuration that names one Vault key, one PEM file or one ``kid`` twice
    is refused here, and ``ValueError`` names both variables. Paths compare as
    resolved absolute paths, so ``/k/./a/../x.pem`` collides with
    ``/k/x.pem``; an unset path collides with nothing.

    The read key is not compared: this service has named none since the
    layer-1 session token, and the api's read key is another deployment's
    configuration, which this process cannot read.
    """
    pairs: list[tuple[str, str | None, str, str | None]] = [
        (
            "POSTERN_VAULT_SESSION_KEY_NAME",
            settings.vault_session_key_name.strip(),
            "POSTERN_VAULT_WRITE_KEY_NAME",
            settings.vault_write_key_name.strip(),
        ),
        (
            "POSTERN_SESSION_KEY_KID",
            settings.session_key_kid,
            "POSTERN_WRITE_KEY_KID",
            settings.write_key_kid,
        ),
    ]
    for session_var, session_value, other_var, other_value in pairs:
        if session_value == other_value:
            raise ValueError(
                f"{session_var} and {other_var} are both {session_value!r}. The session key "
                "must be a different key from the write key, or a token of one kind would "
                "verify as another."
            )
    session_path = settings.session_key_pem_path
    if session_path is None:
        return
    resolved = Path(session_path).expanduser().resolve()
    write_path = settings.write_key_pem_path
    if write_path is not None and Path(write_path).expanduser().resolve() == resolved:
        raise ValueError(
            f"POSTERN_SESSION_KEY_PEM_PATH ({session_path!r}) and POSTERN_WRITE_KEY_PEM_PATH "
            f"({write_path!r}) are the same file. The session key must be a different "
            "key from the write key."
        )


def check_session_token_settings(settings: ConfirmSettings) -> None:
    """Refuse a session-token configuration no deployment may run, or return.

    ``ValueError`` naming the offending values, for each of:

    - ``session_token_issuer`` that is not ``https`` with a hostname, that
      carries a query or a fragment, or that fails
      `postern_core.auth.resource_uri`'s ``is_plain_ascii_uri_text``;
    - ``session_token_issuer`` equal to ``write_token_issuer`` or to
      ``app_assertion_issuer``: one issuer string per token type;
    - ``session_token_audience`` that is not an absolute ``https`` URI with a
      host, already in `postern_core.auth.resource_uri`'s normal form, unless
      ``allow_non_uri_audience`` is set, in which case a warning naming the
      flag is logged instead;
    - a session Vault key name, PEM path or ``kid`` equal to the write key's
      (``_refuse_shared_session_key``);
    - ``session_token_audience`` equal to ``app_assertion_audience``, the
      rule this module's docstring argues from the other side.

    CALLED BY ``create_confirm_app``, NOT BY ``__post_init__``, so a settings
    object built by hand is refused where a deployment would be, at startup,
    and a test that builds one without building an app is unaffected.
    Equality with the api's ``POSTERN_AUDIENCE`` cannot be checked here: that
    is another deployment, and a mismatch fails closed at the api.
    """
    issuer = settings.session_token_issuer
    # The raw-string check runs first: urlsplit deletes tab, CR and LF and
    # strips leading whitespace, so it would judge a different string.
    plain = is_plain_ascii_uri_text(issuer)
    parts = urlsplit(issuer) if plain else None
    if (
        parts is None
        or parts.scheme != "https"
        or not parts.hostname
        or "?" in issuer
        or "#" in issuer
    ):
        raise ValueError(
            f"POSTERN_SESSION_TOKEN_ISSUER ({issuer!r}) must be an https URL with a hostname "
            "and no query or fragment, in pure ASCII with no control character, space, "
            "backslash or %00. It is the iss of every access token POST /token issues."
        )
    for name, other in (
        ("POSTERN_WRITE_TOKEN_ISSUER", settings.write_token_issuer),
        ("POSTERN_APP_ASSERTION_ISSUER", settings.app_assertion_issuer),
    ):
        if issuer == other:
            raise ValueError(
                f"POSTERN_SESSION_TOKEN_ISSUER ({issuer!r}) must differ from {name} ({other!r}). "
                "Each token type carries its own issuer, so no verifier can mistake one for "
                "another."
            )
    _refuse_shared_session_key(settings)
    audience = settings.session_token_audience
    if not is_normal_https_resource(audience):
        if not settings.allow_non_uri_audience:
            raise ValueError(
                f"POSTERN_SESSION_TOKEN_AUDIENCE ({audience!r}) must be the MCP server's "
                "resource URI: an absolute https URI with a host and no fragment (RFC 8707 "
                "section 2), with a lower-case scheme and host, no default port and a "
                "non-empty path. Set it to the same value as services/api's POSTERN_AUDIENCE, "
                "or set POSTERN_ALLOW_NON_URI_AUDIENCE for a local stack."
            )
        logger.warning(
            "POSTERN_ALLOW_NON_URI_AUDIENCE is set: access tokens carry the audience %r, "
            "which is not an absolute https URI. No deployment may run this way.",
            audience,
        )
    if audience == settings.app_assertion_audience:
        raise ValueError(
            f"POSTERN_SESSION_TOKEN_AUDIENCE ({audience!r}) must differ from "
            "POSTERN_APP_ASSERTION_AUDIENCE: a token good enough to reach the MCP server "
            "must not be good enough to approve a payment."
        )

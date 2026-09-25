"""Settings for the write path and device authorization flow.

There is deliberately no read key field here, and no write key field in
services/api/settings.py. The asymmetry is the control, and it is greppable.

Device authorization (§7.3 of the handoff) adds:
- ``device_verification_uri`` — base URI for the user verification page.
  The QR code encodes this + ``user_code``; the mobile app deep-links to it.
- ``device_code_ttl_seconds`` — lifetime of a device code (default 900 = 15
  min), refused below ``MIN_DEVICE_CODE_TTL_SECONDS`` because the Redis store
  cannot represent a shorter one (bug B1; that constant carries the working).
- ``device_poll_interval_seconds`` — minimum seconds between token polls (default 5).

The confirm service also needs a READ key to mint read tokens during device
code exchange (the browser receives the read token after the user approves).
This is a deliberate exception: the device grant flow mints both read and
write tokens in one atomic step, so it needs both keys. The separation is
preserved at startup — no code path hands one process both keys for general
use; the device grant is a controlled exception.

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

import os
from dataclasses import dataclass


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
    """
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    try:
        value = int(raw)
    except ValueError:
        raise ValueError(
            f"{name} must be a positive integer, got {raw!r}. "
            "It is a per-minute request count; there is no value that disables the limit."
        ) from None
    if value < 1:
        raise ValueError(
            f"{name} must be a positive integer, got {value}. "
            "It is a per-minute request count; there is no value that disables the limit."
        )
    return value


#: The shortest device-code lifetime ``POSTERN_DEVICE_CODE_TTL_SECONDS`` accepts.
#:
#: WHY A FLOOR EXISTS AT ALL (bug B1). `postern_core.auth.device_codes`'s
#: `RedisDeviceCodeStore` writes its key with
#: ``max(0, int((expires_at - now).total_seconds()))``, and ``int``
#: TRUNCATES. A code asked for one second has roughly 0.9999 of one left by
#: the time that line runs, so it floors to zero and the ``if ttl_seconds >
#: 0`` guard skips BOTH the ``SETEX`` and the ``ZADD``. Measured on
#: 2026-09-25 against redis:7-alpine::
#:
#:     expires_in=   1  raw=0.999982  int()=0  stored=NO -- nothing written
#:     expires_in=   2  raw=1.999990  int()=1  stored=YES
#:     expires_in= 900  raw=899.999992  int()=899  stored=YES
#:
#: ``create_device_code`` returns a code in all three rows, so the first one
#: hands a browser a device code the store never wrote; its next ``/token``
#: poll is answered ``invalid_grant``, which tells a legitimate customer
#: their code was never real. `InMemoryDeviceCodeStore` stores that same
#: code, so dev and production disagree on the same call. This variable was
#: the only path an operator could reach that from: before this floor it was
#: read with a bare ``int()`` and validated nowhere.
#:
#: WHY 30, DERIVED. Three bounds sit under it, and
#: tests/test_device_grant.py::TestTheFloorIsDerivedAndNotPicked re-derives
#: each one so that this working fails rather than rots:
#:
#: - 2 IS WHERE THE ARITHMETIC BITES. Below it the Redis backend stores
#:   nothing at all; tests/test_redis_backed_stores.py::SHORTEST_STORED_TTL
#:   is that number and carries the same measurement. 30 is 15x it, which is
#:   far enough that no rounding anywhere can reach the cliff.
#: - 5 IS THE BROWSER'S FIRST POLL, ``device_poll_interval_seconds`` below.
#:   `services/confirm/device_auth.py`'s ``token_endpoint`` answers
#:   ``slow_down`` to anything sooner, so a TTL at or under the interval
#:   expires before the browser is permitted to ask even once. 30 is 6x it,
#:   so a code at the floor survives several polls rather than exactly one.
#: - 15 IS THE LONGEST MEASURED SERVER-SIDE LEG of the approval: CLAUDE.md
#:   prices identity verification, which step 4 of the flow in
#:   `postern_core.auth.device_codes` reaches, at 5 to 15 seconds. 30 is 2x
#:   its worst case.
#:
#: WHAT THIS DELIBERATELY DOES NOT CLAIM, because a floor that reads as a
#: recommendation is worse than none:
#:
#: - NOT that 30 is usable. It is not. 900 is the default and the only
#:   lifetime in this tree derived for real use, and an operator who sets 30
#:   will strand customers who take longer than half a minute to pick up a
#:   phone. This bounds what is REPRESENTABLE, not what is SUFFICIENT.
#: - NOT that a human can scan a QR, compare a pairing code and approve
#:   within 30 seconds. Nothing here measures a human, and the number is
#:   built only out of legs this repository has measured.
#: - NOT that the truncation is fixed. It is not; see
#:   `postern_core.auth.device_codes`'s ``_set_code``, which records what
#:   still reaches it. This closes the CONFIGURATION path and no other.
MIN_DEVICE_CODE_TTL_SECONDS = 30


def _device_code_ttl(name: str, default: int) -> int:
    """Read a device-code lifetime from the environment, or refuse to start.

    Deliberately the same shape as `_positive_int` above -- read, refuse,
    echo, name the variable -- rather than a second validation style, and
    for the same stated reason: a value an operator typed and got wrong must
    fail when the app is assembled, not silently revert to a default they
    did not choose. What differs is only the bound, because the quantity is
    a duration rather than a per-minute count, and `MIN_DEVICE_CODE_TTL_SECONDS`
    carries its derivation.

    THE CEILING IS DELIBERATELY ABSENT. A lifetime that is too LONG is a
    real risk -- it widens the window in which a leaked ``device_code`` is
    worth relaying (A2) -- but it is a risk an operator can reason about and
    RFC 8628 sets no bound on. A value that is too SHORT is different in
    kind: it does not weaken a control, it produces a service that cannot
    complete a pairing at all, and on the Redis backend it does so silently.
    Only the second one is unrepresentable, so only the second one is
    refused here.

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
    return value


@dataclass(frozen=True)
class ConfirmSettings:
    write_key_pem_path: str | None = None
    write_key_kid: str = "write-1"
    write_token_issuer: str = "https://mcp-write.internal"  # noqa: S105
    # Device authorization (§7.3): where the user goes to approve pairing.
    device_verification_uri: str = "https://auth.postern.internal/verify"
    # Floored at `MIN_DEVICE_CODE_TTL_SECONDS` when it comes from the
    # environment, which is where that constant's working lives. The field
    # default stays 900 and is the only lifetime here derived for real use.
    device_code_ttl_seconds: int = 900
    device_poll_interval_seconds: int = 5
    # Read key for device grant token exchange (both read + write needed here).
    read_key_pem_path: str | None = None
    read_key_kid: str = "read-1"
    read_token_issuer: str = "https://mcp-read.internal"  # noqa: S105
    # Approval callback (§6.3, §8.3): backend write endpoints + challenges DB.
    backend_base_url: str = "https://backend.internal"  # noqa: S105
    database_url: str = "postgresql+asyncpg://postern:postern@localhost:5432/postern"
    database_connect_timeout_seconds: float = 2.0
    database_command_timeout_seconds: float = 3.0
    database_pool_timeout_seconds: float = 1.0
    # Inbound app assertion (C-01, C-02). All three required; see the module
    # docstring for why there is no audience default and why this service,
    # unlike `services/api`, has no no-auth path at all.
    app_assertion_jwks_uri: str | None = None
    app_assertion_issuer: str | None = None
    app_assertion_audience: str | None = None
    # Enrolled device public keys, the input to the approval signature check
    # (`services/confirm/device_signature.py`). A path rather than a
    # connection string, and a field here rather than an environment variable
    # read inside a factory the way `create_revocation_store` and
    # `create_device_code_store` read `POSTERN_REDIS_URL`: this is key
    # material the operator renders, so it follows `read_key_pem_path` and
    # `write_key_pem_path` above, and `postern_core.auth.device_keys` records
    # at length why enrolment data must not share the cache's variable.
    #
    # REQUIRED, with no default, exactly like the three assertion fields:
    # `create_confirm_app` refuses to build without it. A default would be a
    # path the operator never typed, and the failure mode of getting it wrong
    # is a service that cannot approve anything -- which is fail-closed, and
    # is still an outage an operator must meet at startup rather than at the
    # first payment.
    device_keys_path: str | None = None
    # RFC 8628 §5.2: bound `user_code` guessing. Three tolerates a user
    # mistyping the pairing code on the app's screen; the fourth failure
    # revokes the device code outright, which forces a fresh QR and so
    # re-anchors the human code comparison that is the actual A2 control.
    user_code_max_attempts: int = 3
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
    #   `grant_type` plus a 43-character device code; `/approve` carries two
    #   short codes. 64 KiB is ~220x the largest of those and 8x the floor,
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
    # 41 characters ("accounts:read transactions:read cards:read"), and the
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
    # - CARRIER-GRADE NAT, on the two public paths. A mobile carrier can put
    #   thousands of subscribers behind one IPv4 address, so a browser-facing
    #   limit low enough to bite an attacker holding a handful of addresses is
    #   low enough to hurt a real NAT pool. The defaults are set on the side
    #   that does not break customers, and the store cap rather than this is
    #   what bounds memory.
    # - THE APP BACKEND, on the two assertion-authenticated paths, and this is
    #   the one that will hurt if it is wrong. ``rate_limit_approve`` and
    #   ``rate_limit_challenge_approve`` default to 60/min per bucket, which
    #   is right if the operator's banking app calls this service FROM THE
    #   CUSTOMER'S PHONE, because then the addresses are as diverse as the
    #   customers. If instead the app's BACKEND calls on the phone's behalf,
    #   every approval in the bank arrives from a handful of egress addresses
    #   and 60/min becomes a bank-wide ceiling on payment approvals. An
    #   operator in that shape must raise these two, and the fact that it is
    #   an environment variable rather than a release is the whole point:
    #   discovering it at 3am costs a restart, not a deploy.
    #
    # The honest limit of all five: a per-address bound is the wrong UNIT for
    # an authenticated path, where the meaningful one is per customer. Keying
    # the assertion-authenticated paths on the verified ``sub`` needs a second
    # limiter running AFTER ``AppAssertionMiddleware``, which is a different
    # shape from the outermost one these configure; see
    # `services/confirm/rate_limit.py`'s module docstring.
    rate_limit_device_authorization: int = 60
    rate_limit_token: int = 300
    rate_limit_approve: int = 60
    rate_limit_challenge_approve: int = 60
    rate_limit_default: int = 60

    @classmethod
    def from_env(cls) -> "ConfirmSettings":
        return cls(
            write_key_pem_path=os.environ.get("POSTERN_WRITE_KEY_PEM_PATH") or None,
            write_key_kid=os.environ.get("POSTERN_WRITE_KEY_KID", "write-1"),
            write_token_issuer=os.environ.get(
                "POSTERN_WRITE_TOKEN_ISSUER", "https://mcp-write.internal"
            ),
            device_verification_uri=os.environ.get(
                "POSTERN_DEVICE_VERIFICATION_URI",
                "https://auth.postern.internal/verify",
            ),
            device_code_ttl_seconds=_device_code_ttl("POSTERN_DEVICE_CODE_TTL_SECONDS", 900),
            device_poll_interval_seconds=int(
                os.environ.get("POSTERN_DEVICE_POLL_INTERVAL_SECONDS", "5")
            ),
            read_key_pem_path=os.environ.get("POSTERN_READ_KEY_PEM_PATH") or None,
            read_key_kid=os.environ.get("POSTERN_READ_KEY_KID", "read-1"),
            read_token_issuer=os.environ.get(
                "POSTERN_READ_TOKEN_ISSUER", "https://mcp-read.internal"
            ),
            backend_base_url=os.environ.get("POSTERN_BACKEND_BASE_URL", "https://backend.internal"),
            database_url=os.environ.get(
                "POSTERN_DATABASE_URL",
                "postgresql+asyncpg://postern:postern@localhost:5432/postern",
            ),
            database_connect_timeout_seconds=float(
                os.environ.get("POSTERN_DATABASE_CONNECT_TIMEOUT_SECONDS", "2.0")
            ),
            database_command_timeout_seconds=float(
                os.environ.get("POSTERN_DATABASE_COMMAND_TIMEOUT_SECONDS", "3.0")
            ),
            database_pool_timeout_seconds=float(
                os.environ.get("POSTERN_DATABASE_POOL_TIMEOUT_SECONDS", "1.0")
            ),
            app_assertion_jwks_uri=os.environ.get("POSTERN_APP_ASSERTION_JWKS_URI") or None,
            app_assertion_issuer=os.environ.get("POSTERN_APP_ASSERTION_ISSUER") or None,
            app_assertion_audience=os.environ.get("POSTERN_APP_ASSERTION_AUDIENCE") or None,
            device_keys_path=os.environ.get("POSTERN_DEVICE_KEYS_PATH") or None,
            user_code_max_attempts=int(os.environ.get("POSTERN_USER_CODE_MAX_ATTEMPTS", "3")),
            max_body_bytes=int(
                os.environ.get("POSTERN_CONFIRM_MAX_BODY_BYTES", str(65_536)),
            ),
            trusted_proxy_hops=int(os.environ.get("POSTERN_CONFIRM_TRUSTED_PROXY_HOPS", "0")),
            max_device_codes=int(os.environ.get("POSTERN_MAX_DEVICE_CODES", str(10_000))),
            max_scopes_length=int(os.environ.get("POSTERN_MAX_SCOPES_LENGTH", str(512))),
            max_client_id_length=int(os.environ.get("POSTERN_MAX_CLIENT_ID_LENGTH", str(256))),
            rate_limit_device_authorization=_positive_int(
                "POSTERN_CONFIRM_RATE_LIMIT_DEVICE_AUTHORIZATION", 60
            ),
            rate_limit_token=_positive_int("POSTERN_CONFIRM_RATE_LIMIT_TOKEN", 300),
            rate_limit_approve=_positive_int("POSTERN_CONFIRM_RATE_LIMIT_APPROVE", 60),
            rate_limit_challenge_approve=_positive_int(
                "POSTERN_CONFIRM_RATE_LIMIT_CHALLENGE_APPROVE", 60
            ),
            rate_limit_default=_positive_int("POSTERN_CONFIRM_RATE_LIMIT_DEFAULT", 60),
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
        )

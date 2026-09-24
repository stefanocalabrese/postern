"""Settings for the write path and device authorization flow.

There is deliberately no read key field here, and no write key field in
services/api/settings.py. The asymmetry is the control, and it is greppable.

Device authorization (§7.3 of the handoff) adds:
- ``device_verification_uri`` — base URI for the user verification page.
  The QR code encodes this + ``user_code``; the mobile app deep-links to it.
- ``device_code_ttl_seconds`` — lifetime of a device code (default 900 = 15 min).
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


@dataclass(frozen=True)
class ConfirmSettings:
    write_key_pem_path: str | None = None
    write_key_kid: str = "write-1"
    write_token_issuer: str = "https://mcp-write.internal"  # noqa: S105
    # Device authorization (§7.3): where the user goes to approve pairing.
    device_verification_uri: str = "https://auth.postern.internal/verify"
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
    #   which leaves room for the per-customer device signature
    #   `services/confirm/callback.py`'s docstring says this path still owes
    #   (an RSA-4096 signature is 684 base64 characters) without leaving room
    #   for a megabyte.
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
            device_code_ttl_seconds=int(os.environ.get("POSTERN_DEVICE_CODE_TTL_SECONDS", "900")),
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
            user_code_max_attempts=int(os.environ.get("POSTERN_USER_CODE_MAX_ATTEMPTS", "3")),
            max_body_bytes=int(
                os.environ.get("POSTERN_CONFIRM_MAX_BODY_BYTES", str(65_536)),
            ),
        )

    @classmethod
    def for_testing(cls) -> "ConfirmSettings":
        """Settings that build an app which authenticates NOBODY successfully.

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

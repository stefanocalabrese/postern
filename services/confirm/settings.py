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
            device_code_ttl_seconds=int(
                os.environ.get("POSTERN_DEVICE_CODE_TTL_SECONDS", "900")
            ),
            device_poll_interval_seconds=int(
                os.environ.get("POSTERN_DEVICE_POLL_INTERVAL_SECONDS", "5")
            ),
            read_key_pem_path=os.environ.get("POSTERN_READ_KEY_PEM_PATH") or None,
            read_key_kid=os.environ.get("POSTERN_READ_KEY_KID", "read-1"),
            read_token_issuer=os.environ.get(
                "POSTERN_READ_TOKEN_ISSUER", "https://mcp-read.internal"
            ),
        )

    @classmethod
    def for_testing(cls) -> "ConfirmSettings":
        return cls()

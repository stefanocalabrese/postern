"""Settings for the write path.

There is deliberately no read key field here, and no write key field in
services/api/settings.py. The asymmetry is the control, and it is greppable.
"""

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class ConfirmSettings:
    write_key_pem_path: str | None = None
    write_key_kid: str = "write-1"
    write_token_issuer: str = "https://mcp-write.internal"  # noqa: S105

    @classmethod
    def from_env(cls) -> "ConfirmSettings":
        return cls(
            write_key_pem_path=os.environ.get("POSTERN_WRITE_KEY_PEM_PATH") or None,
            write_key_kid=os.environ.get("POSTERN_WRITE_KEY_KID", "write-1"),
            write_token_issuer=os.environ.get(
                "POSTERN_WRITE_TOKEN_ISSUER", "https://mcp-write.internal"
            ),
        )

    @classmethod
    def for_testing(cls) -> "ConfirmSettings":
        return cls()

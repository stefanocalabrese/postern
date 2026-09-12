"""Runtime configuration for the API service (Task 4)."""

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    backend_base_url: str
    customer_jwks_uri: str | None = None
    customer_token_issuer: str | None = None
    audience: str = "postern"
    strict_headers: bool = False
    cache_ttl_seconds: int = 60

    @classmethod
    def from_env(cls) -> "Settings":
        """`os.environ[...]` for the three with no safe default, so a missing
        one fails at startup with a `KeyError` naming it, rather than at the
        first customer request.
        """
        return cls(
            backend_base_url=os.environ["POSTERN_BACKEND_BASE_URL"],
            customer_jwks_uri=os.environ["POSTERN_JWKS_URI"],
            customer_token_issuer=os.environ["POSTERN_TOKEN_ISSUER"],
            audience=os.environ.get("POSTERN_AUDIENCE", "postern"),
            strict_headers=os.environ.get("POSTERN_STRICT_HEADERS") == "1",
            cache_ttl_seconds=int(os.environ.get("POSTERN_CACHE_TTL_SECONDS", "60")),
        )

    @classmethod
    def for_testing(cls) -> "Settings":
        return cls(backend_base_url="https://backend.test")

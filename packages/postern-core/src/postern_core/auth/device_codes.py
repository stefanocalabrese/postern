"""RFC 8628 Device Authorization Grant — device codes and storage.

Provides the ``DeviceCode`` model and a pluggable ``DeviceCodeStore`` backed
by either an in-memory dict (dev / test) or Redis (production — compatible
with AWS ElastiCache, Google Memorystore, Azure Cache for Redis, or any
Redis-compatible service).

The device authorization flow (§7.3 of the handoff):

1. Browser calls ``/device_authorization`` → gets a device code and a
   user-visible pairing code (6 chars).
2. A QR code encodes the verification URI + pairing code.
3. User scans with mobile app → bank app shows pairing code + context.
4. User confirms pairing code matches → proceeds to identity verification.
5. After approval, the browser polls ``/token`` with
   ``grant_type=device_code`` to receive access tokens.

The pairing code (``user_code``) is the critical anti-phishing control:
it must match on both surfaces before identity verification proceeds.

Usage::

    from postern_core.auth.device_codes import InMemoryDeviceStore

    store = InMemoryDeviceCodeStore()
    code = await store.create_device_code(
        client_id="my-client",
        scopes="accounts:read transactions:read",
    )
    # code.device_code, code.user_code, code.verification_uri ...

    # Later: check if approved
    existing = await store.get_device_code(code.device_code)
    if existing and existing.approved:
        # Browser can exchange for tokens
        pass

Production deployments set ``POSTERN_REDIS_URL`` to enable the Redis
backend; without it, the in-memory store is used.
"""

from __future__ import annotations

import os
import secrets
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

logger = __import__("logging").getLogger(__name__)


# ---------------------------------------------------------------------------
# DeviceCode — the core model.
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class DeviceCode:
    """An RFC 8628 device authorization session.

    All fields come from the spec or are extensions needed by Postern's
    QR pairing flow.

    Attributes:
        device_code: Opaque 40+ char code the browser exchanges at /token.
        user_code: Human-readable pairing code (6 chars, shown as XXX-XXX).
        verification_uri: URI the user visits on mobile (e.g. auth page).
        expires_at: When this device code expires (UTC).
        interval: Seconds between token polls (default 5).
        client_id: OAuth client identifier.
        scopes: Space-separated scope list from the request.
        approved: Whether mobile app has approved this session.
        approved_at: When approval happened (None until approved).
    """

    device_code: str
    user_code: str
    verification_uri: str
    expires_at: datetime
    interval: int = 5
    client_id: str = ""
    scopes: str = ""
    approved: bool = False
    approved_at: datetime | None = None

    @property
    def user_code_display(self) -> str:
        """Return the pairing code as XXX-XXX for display."""
        if len(self.user_code) >= 6:
            return f"{self.user_code[:3]}-{self.user_code[3:6]}"
        return self.user_code

    @property
    def is_expired(self) -> bool:
        """Whether this device code has passed its expiry."""
        return datetime.now(UTC) >= self.expires_at

    @property
    def verification_uri_complete(self) -> str:
        """Verification URI with user_code as query parameter for deep-linking."""
        separator = "&" if "?" in self.verification_uri else "?"
        return f"{self.verification_uri}{separator}user_code={self.user_code}"

    def to_json(self) -> str:
        """Serialize to JSON string."""
        return _json.dumps(_device_code_to_dict(self))

    @classmethod
    def from_json(cls, data: str) -> DeviceCode:
        """Deserialize from JSON string."""
        return _device_code_from_dict(_json.loads(data))

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a plain dict."""
        return _device_code_to_dict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> DeviceCode:
        """Deserialize from a plain dict."""
        return _device_code_from_dict(data)


# ---------------------------------------------------------------------------
# Abstract base class — the interface all backends must implement.
# ---------------------------------------------------------------------------

class DeviceCodeStoreBase(ABC):
    """Abstract base class for device code stores.

    All backends (in-memory, Redis) must implement these methods.
    The factory ``create_device_code_store()`` returns the appropriate
    implementation based on environment configuration.

    All methods are async — even the in-memory store uses ``async def`` so
    callers can uniformly ``await store.xxx()`` regardless of backend.
    """

    @abstractmethod
    async def create_device_code(
        self,
        *,
        client_id: str,
        scopes: str,
        verification_uri: str,
        expires_in: int = 900,
        interval: int = 5,
    ) -> DeviceCode:
        """Create a new device code session and return it."""

    @abstractmethod
    async def get_device_code(self, device_code: str) -> DeviceCode | None:
        """Look up a device code by its opaque value, or ``None``."""

    @abstractmethod
    async def approve_device_code(self, device_code: str) -> bool:
        """Mark a device code as approved. Returns True if found and updated."""

    @abstractmethod
    async def revoke_device_code(self, device_code: str) -> None:
        """Remove a device code (e.g. on explicit cancellation)."""

    @abstractmethod
    async def update_device_code(self, device_code: str, code: DeviceCode) -> None:
        """Replace a device code with an updated version.

        Used by the approval callback to attach the customer identity
        (subject_value) after the user approves on mobile.
        """


# ---------------------------------------------------------------------------
# In-memory backend (default for dev / test).
# ---------------------------------------------------------------------------

def _generate_device_code() -> str:
    """Generate a cryptographically random device code (40+ chars)."""
    return secrets.token_urlsafe(32)  # 43 chars


def _generate_user_code() -> str:
    """Generate a 6-char alphanumeric user code (pairing code)."""
    # RFC 8628 §3.1: user codes are case-insensitive, 6+ chars,
    # all upper-case letters and digits only.
    alphabet = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"  # no ambiguous chars
    return "".join(secrets.choice(alphabet) for _ in range(6))


class InMemoryDeviceCodeStore(DeviceCodeStoreBase):
    """In-memory store mapping ``device_code`` → ``DeviceCode``.

    Thread-safe enough for FastMCP's in-process test client (single-threaded
    async). Not safe across processes — use ``RedisDeviceCodeStore`` for that.

    Methods are ``async def`` so callers can uniformly ``await store.xxx()``
    regardless of which backend the factory returned.
    """

    def __init__(self) -> None:
        self._codes: dict[str, DeviceCode] = {}

    async def create_device_code(
        self,
        *,
        client_id: str,
        scopes: str,
        verification_uri: str,
        expires_in: int = 900,
        interval: int = 5,
    ) -> DeviceCode:
        """Create a new device code session and return it."""
        device_code = _generate_device_code()
        user_code = _generate_user_code()
        expires_at = datetime.now(UTC) + timedelta(seconds=expires_in)
        code = DeviceCode(
            device_code=device_code,
            user_code=user_code,
            verification_uri=verification_uri,
            expires_at=expires_at,
            interval=interval,
            client_id=client_id,
            scopes=scopes,
        )
        self._codes[device_code] = code
        return code

    async def get_device_code(self, device_code: str) -> DeviceCode | None:
        """Look up a device code by its opaque value, or ``None``."""
        return self._codes.get(device_code)

    async def approve_device_code(self, device_code: str) -> bool:
        """Mark a device code as approved. Returns True if found and updated."""
        existing = self._codes.get(device_code)
        if existing is None or existing.approved:
            return False
        # Dataclass is frozen, so we replace with a new instance.
        self._codes[device_code] = existing.__class__(
            **{**asdict_frozen(existing), "approved": True, "approved_at": datetime.now(UTC)}
        )
        return True

    async def revoke_device_code(self, device_code: str) -> None:
        """Remove a device code."""
        self._codes.pop(device_code, None)

    async def update_device_code(self, device_code: str, code: DeviceCode) -> None:
        """Replace a device code with an updated version."""
        self._codes[device_code] = code


def asdict_frozen(obj: Any) -> dict[str, Any]:
    """Convert a frozen dataclass to a mutable dict."""
    import dataclasses

    if not dataclasses.is_dataclass(obj):
        raise TypeError(f"Expected a dataclass, got {type(obj).__name__}")
    return {f.name: getattr(obj, f.name) for f in dataclasses.fields(obj)}


# ---------------------------------------------------------------------------
# Redis backend — compatible with AWS ElastiCache, Google Memorystore, etc.
# ---------------------------------------------------------------------------

class RedisDeviceCodeStore(DeviceCodeStoreBase):
    """Redis-backed device code store.

    Compatible with any Redis-compatible service: AWS ElastiCache for
    Redis, Google Memorystore for Redis, Azure Cache for Redis, or a
    self-hosted Redis instance.

    Device codes are stored as JSON with a TTL matching the code's expiry.
    The ``expires_at`` field is a POSIX timestamp, so codes survive process
    restarts.

    Configuration via environment variables:

    ``POSTERN_REDIS_URL``
        Redis connection string, e.g. ``redis://localhost:6379/0`` or
        ``rediss://user:pass@host:port/0`` (TLS).

    ``POSTERN_REDIS_DEVICE_CODE_TTL``
        Default TTL in seconds for new device codes (default 900 = 15 min).

    ``POSTERN_REDIS_KEY_PREFIX``
        Key prefix for multi-tenant deployments (default ``"postern:"``).

    Usage::

        store = RedisDeviceCodeStore()
        code = await store.create_device_code(
            client_id="my-client", scopes="accounts:read"
        )
        existing = await store.get_device_code(code.device_code)  # DeviceCode | None
    """

    def __init__(
        self,
        url: str | None = None,
        default_ttl: int | None = None,
        key_prefix: str | None = None,
    ) -> None:
        import redis.asyncio as redis

        self._url = url or os.environ.get("POSTERN_REDIS_URL", "redis://localhost:6379/0")
        self._default_ttl = default_ttl or int(
            os.environ.get("POSTERN_REDIS_DEVICE_CODE_TTL", "900")
        )
        self._prefix = key_prefix or os.environ.get("POSTERN_REDIS_KEY_PREFIX", "postern:")
        self._redis: Any = redis.from_url(  # type: ignore[no-untyped-call]
            self._url,
            decode_responses=True,
        )

    def _key(self, device_code: str) -> str:
        """Build the Redis key for a device code."""
        return f"{self._prefix}device:{device_code}"

    async def create_device_code(
        self,
        *,
        client_id: str,
        scopes: str,
        verification_uri: str,
        expires_in: int | None = None,
        interval: int = 5,
    ) -> DeviceCode:
        """Create a new device code session and return it."""
        device_code = _generate_device_code()
        user_code = _generate_user_code()
        expires_in = expires_in or self._default_ttl
        expires_at = datetime.now(UTC) + timedelta(seconds=expires_in)
        code = DeviceCode(
            device_code=device_code,
            user_code=user_code,
            verification_uri=verification_uri,
            expires_at=expires_at,
            interval=interval,
            client_id=client_id,
            scopes=scopes,
        )
        await self._set_code(device_code, code)
        return code

    async def get_device_code(self, device_code: str) -> DeviceCode | None:
        """Look up a device code by its opaque value, or ``None``."""
        data = await self._redis.get(self._key(device_code))
        if data is None:
            return None
        try:
            return DeviceCode.from_json(data)
        except (KeyError, ValueError, TypeError) as exc:  # pragma: no cover
            logger.warning("Failed to deserialize device code %s: %s", device_code, exc)
            return None

    async def approve_device_code(self, device_code: str) -> bool:
        """Mark a device code as approved. Returns True if found and updated."""
        existing = await self.get_device_code(device_code)
        if existing is None or existing.approved:
            return False
        updated = DeviceCode(
            **{**asdict_frozen(existing), "approved": True, "approved_at": datetime.now(UTC)}
        )
        await self._set_code(device_code, updated)
        return True

    async def revoke_device_code(self, device_code: str) -> None:
        """Remove a device code."""
        await self._redis.delete(self._key(device_code))

    async def update_device_code(self, device_code: str, code: DeviceCode) -> None:
        """Replace a device code with an updated version."""
        await self._set_code(device_code, code)

    async def _set_code(self, device_code: str, code: DeviceCode) -> None:
        """Store a device code with TTL."""
        ttl_seconds = max(0, int((code.expires_at - datetime.now(UTC)).total_seconds()))
        if ttl_seconds > 0:
            await self._redis.setex(
                self._key(device_code),
                ttl_seconds,
                code.to_json(),
            )

    async def close(self) -> None:
        """Close the Redis connection pool."""
        await self._redis.aclose()


# ---------------------------------------------------------------------------
# Serialization helpers — add to DeviceCode dataclass.
# ---------------------------------------------------------------------------

# We patch the frozen dataclass with serialization methods after definition.
# This avoids making the class non-frozen while still supporting Redis storage.

import dataclasses
import json as _json
from datetime import UTC as _UTC


def _device_code_to_dict(dc: DeviceCode) -> dict[str, Any]:
    """Serialize a DeviceCode to a plain dict."""
    return {
        "device_code": dc.device_code,
        "user_code": dc.user_code,
        "verification_uri": dc.verification_uri,
        "expires_at": dc.expires_at.timestamp(),
        "interval": dc.interval,
        "client_id": dc.client_id,
        "scopes": dc.scopes,
        "approved": dc.approved,
        "approved_at": dc.approved_at.timestamp() if dc.approved_at else None,
    }


def _device_code_from_dict(data: dict[str, Any]) -> DeviceCode:
    """Deserialize a DeviceCode from a plain dict."""
    approved_at = None
    if data.get("approved_at") is not None:
        approved_at = datetime.fromtimestamp(data["approved_at"], tz=_UTC)
    return DeviceCode(
        device_code=data["device_code"],
        user_code=data["user_code"],
        verification_uri=data["verification_uri"],
        expires_at=datetime.fromtimestamp(data["expires_at"], tz=_UTC),
        interval=data.get("interval", 5),
        client_id=data.get("client_id", ""),
        scopes=data.get("scopes", ""),
        approved=bool(data.get("approved", False)),
        approved_at=approved_at,
    )


# ---------------------------------------------------------------------------
# Factory — picks the right backend based on environment.
# ---------------------------------------------------------------------------

def create_device_code_store() -> DeviceCodeStoreBase:
    """Create a device code store backed by the configured backend.

    Reads ``POSTERN_REDIS_URL``: if set, returns a
    ``RedisDeviceCodeStore``; otherwise returns an ``InMemoryDeviceCodeStore``.

    This is the recommended entry point for production code:

    .. code-block:: python

        store = create_device_code_store()  # auto-selects backend
    """
    redis_url = os.environ.get("POSTERN_REDIS_URL")
    if redis_url:
        logger.info("Using Redis device code store (url=%s)", redis_url)
        return RedisDeviceCodeStore(url=redis_url)
    logger.info("Using in-memory device code store (set POSTERN_REDIS_URL for Redis)")
    return InMemoryDeviceCodeStore()


# ---------------------------------------------------------------------------
# Backwards-compatible alias.
# ---------------------------------------------------------------------------

#: Alias for ``InMemoryDeviceCodeStore`` — kept so existing imports work.
#: New code should use :func:`create_device_code_store` instead.
DeviceCodeStore = InMemoryDeviceCodeStore


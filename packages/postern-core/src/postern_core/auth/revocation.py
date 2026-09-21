"""ZT-7 — Revocation list for per-session, per-customer+client, and kill-switch scopes.

Three revocation scopes map to the three acceptance criteria in the zero-trust
plan §4:

1. **Per-session** — revoke one ``jti`` (one device, one client) without
   affecting the customer's other sessions.
2. **Per-customer + per-client** — revoke all sessions for a customer–client
   pair (the "connected-app list" cut).
3. **Per-client kill switch** — revoke every session from one client across
   all customers (the "disable one AI vendor" switch).

The list is in-memory and stateless — no persistence, no baseline learning.
A production deployment would back this with Redis or a database table; the
stub implementation here is sufficient for local testing and CI.

Usage:
    revocation = RevocationList()
    # Per-session revocation (one device, one client)
    revocation.revoke_session(
        jti="uuid-123",
        customer_ref=CustomerRef("cust_7f3a"),
        client_id="vendor-claude",
    )
    # Per-customer + per-client revocation (connected-app list)
    revocation.revoke_customer_client(
        customer_ref=CustomerRef("cust_7f3a"),
        client_id="vendor-claude",
    )
    # Per-client kill switch (disable one AI vendor for all customers)
    revocation.kill_switch(client_id="vendor-claude")

    # Check a token — returns True if the token is revoked
    claims = {"jti": "uuid-123", "sub": "cust_7f3a", "client_id": "vendor-claude"}
    assert revocation.is_revoked(claims)  # True — session revoked

See ``tests/test_zt7_revocation.py`` for the full test matrix.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class RevocationEntry:
    """One revocation record. Immutable so it can be stored in sets/frozensets."""

    jti: str | None = None
    """Session-level revocation: unique per token (UUID)."""

    customer_ref: str | None = None
    """Customer-level scope: the ``sub`` from the token."""

    client_id: str | None = None
    """Client-level scope: the ``client_id`` from the token (optional)."""

    @property
    def is_kill_switch(self) -> bool:
        """True if this entry revokes all sessions for a client (no customer, no jti)."""
        return self.jti is None and self.customer_ref is None and self.client_id is not None

    @property
    def is_customer_client(self) -> bool:
        """True if this entry revokes all sessions for a customer–client pair."""
        return self.jti is None and self.customer_ref is not None and self.client_id is not None

    @property
    def is_session(self) -> bool:
        """True if this entry revokes exactly one session (has jti)."""
        return self.jti is not None


class RevocationList:
    """In-memory revocation list with three scopes.

    Thread-safe for the common case (single-threaded ASGI app). A production
    deployment would back this with Redis or a database table.

    Uses O(1) set lookups per scope (audit fix 2026-09-21): three separate
    sets indexed by the lookup key rather than one set requiring iteration.

    The check order matters: session revocation is checked first (most
    specific), then customer+client, then kill switch (least specific).
    This means a killed client's sessions are also caught by the session check.
    """

    def __init__(self) -> None:
        # O(1) lookup by jti — session revocation is the most specific scope.
        self._session_jtis: set[str] = set()
        # O(1) lookup by (customer_ref, client_id) — connected-app list.
        self._customer_client: set[tuple[str, str]] = set()
        # O(1) lookup by client_id — kill switch.
        self._kill_switch: set[str] = set()

    def revoke_session(
        self,
        *,
        jti: str,
        customer_ref: str | None = None,
        client_id: str | None = None,
    ) -> None:
        """Revoke one session by its ``jti`` (ZT-7, per-session scope).

        This is the most specific revocation: only the token with this ``jti``
        is rejected. The customer's other sessions continue to work.

        Args:
            jti: The JWT ID from the token's claims (unique per token).
            customer_ref: Optional, for audit logging. Not used in the check
                (the jti alone is sufficient).
            client_id: Optional, for audit logging. Not used in the check.
        """
        self._session_jtis.add(jti)

    def revoke_customer_client(
        self,
        *,
        customer_ref: str,
        client_id: str,
    ) -> None:
        """Revoke all sessions for a customer–client pair (ZT-7, connected-app scope).

        This is the "connected-app list" cut: the customer opens their bank app,
        sees the AI vendor in their connected-apps list, and revokes it. All
        sessions from that customer–client pair are rejected immediately.

        Args:
            customer_ref: The ``sub`` from the token (opaque customer identifier).
            client_id: The OAuth client ID of the AI vendor.
        """
        self._customer_client.add((customer_ref, client_id))

    def kill_switch(self, *, client_id: str) -> None:
        """Revoke every session from one client across all customers (ZT-7, kill switch).

        This is the "disable one AI vendor" switch. Every token carrying this
        ``client_id`` — regardless of customer or jti — is rejected immediately.

        Args:
            client_id: The OAuth client ID of the AI vendor to disable.
        """
        self._kill_switch.add(client_id)

    def is_revoked(self, claims: dict[str, Any]) -> bool:
        """Check whether a token's claims are revoked.

        Returns True if any revocation entry matches the claims. The check
        order is: session (most specific) → customer+client → kill switch
        (least specific). All lookups are O(1) set membership tests.

        Args:
            claims: The JWT claims dict (at minimum ``jti``, ``sub``, and
                optionally ``client_id``).

        Returns:
            True if the token is revoked, False otherwise.
        """
        jti = claims.get("jti")
        customer_ref = claims.get("sub")
        client_id = claims.get("client_id")

        # 1. Session revocation (most specific: jti alone) — O(1).
        if jti is not None and jti in self._session_jtis:
            return True

        # 2. Customer + client revocation (connected-app list) — O(1).
        if customer_ref is not None and client_id is not None:
            if (customer_ref, client_id) in self._customer_client:
                return True

        # 3. Kill switch (least specific: any token with this client_id) — O(1).
        if client_id is not None and client_id in self._kill_switch:
            return True

        return False

    def clear(self) -> None:
        """Remove all revocation entries. Useful for tests."""
        self._session_jtis.clear()
        self._customer_client.clear()
        self._kill_switch.clear()

    @property
    def entry_count(self) -> int:
        """Number of revocation entries (for testing/monitoring)."""
        return len(self._session_jtis) + len(self._customer_client) + len(self._kill_switch)

    def get_entries_by_scope(
        self,
    ) -> dict[str, int]:
        """Count entries by scope type. Useful for testing."""
        return {
            "session": len(self._session_jtis),
            "customer_client": len(self._customer_client),
            "kill_switch": len(self._kill_switch),
        }

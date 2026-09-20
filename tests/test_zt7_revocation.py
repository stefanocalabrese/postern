"""ZT-7 — Revocation mechanism tests.

Covers all three revocation scopes from the zero-trust plan §4:
1. Per-session (one jti) — one device, one client, no collateral effect.
2. Per-customer + per-client (connected-app list) — customer cuts one vendor.
3. Per-client kill switch — disable one AI vendor for all customers.

Also covers: no false positives, scope isolation (revoking session doesn't
affect other sessions), and the entry_count/get_entries_by_scope helpers.

See ``postern_core.auth.revocation.RevocationList`` for the API.
"""

import pytest
from postern_core.auth.revocation import RevocationEntry, RevocationList

# --- Helpers ---


def _make_revocation() -> RevocationList:
    """Fresh revocation list for each test."""
    return RevocationList()


# --- Per-session revocation (ZT-7, most specific) ---


def test_session_revocation_rejects_token_with_matching_jti() -> None:
    """Revoking a jti rejects only that token."""
    rev = _make_revocation()
    rev.revoke_session(
        jti="uuid-session-1",
        customer_ref="cust_7f3a",
        client_id="vendor-claude",
    )

    assert rev.is_revoked(
        {"jti": "uuid-session-1", "sub": "cust_7f3a", "client_id": "vendor-claude"}
    )
    assert not rev.is_revoked(
        {"jti": "uuid-session-2", "sub": "cust_7f3a", "client_id": "vendor-claude"}
    )
    # jti is globally unique per token, so the same jti with a different customer
    # is still revoked (this should never happen in practice — jtis are UUIDs).
    assert rev.is_revoked(
        {"jti": "uuid-session-1", "sub": "cust_9b21", "client_id": "vendor-claude"}
    )


def test_session_revocation_no_collateral_effect() -> None:
    """Revoking one session does not affect the customer's other sessions."""
    rev = _make_revocation()
    rev.revoke_session(jti="uuid-session-1", customer_ref="cust_7f3a")

    # Same customer, different jti → not revoked
    assert not rev.is_revoked({"jti": "uuid-session-2", "sub": "cust_7f3a"})
    # Different customer, same jti → still revoked (jti is unique per token)
    assert rev.is_revoked({"jti": "uuid-session-1", "sub": "cust_9b21"})


def test_session_revocation_without_optional_fields() -> None:
    """Session revocation works even when customer_ref and client_id are absent."""
    rev = _make_revocation()
    rev.revoke_session(jti="uuid-session-1")

    assert rev.is_revoked({"jti": "uuid-session-1"})
    assert not rev.is_revoked({"jti": "uuid-session-2"})


# --- Per-customer + per-client revocation (ZT-7, connected-app list) ---


def test_customer_client_revocation_rejects_all_sessions_for_pair() -> None:
    """Revoking a customer–client pair rejects all their sessions."""
    rev = _make_revocation()
    rev.revoke_customer_client(customer_ref="cust_7f3a", client_id="vendor-claude")

    # Same customer + same client → revoked (any jti)
    assert rev.is_revoked({"jti": "uuid-1", "sub": "cust_7f3a", "client_id": "vendor-claude"})
    assert rev.is_revoked({"jti": "uuid-2", "sub": "cust_7f3a", "client_id": "vendor-claude"})
    # Same customer, different client → not revoked
    assert not rev.is_revoked({"jti": "uuid-1", "sub": "cust_7f3a", "client_id": "vendor-chatgpt"})
    # Different customer, same client → not revoked
    assert not rev.is_revoked({"jti": "uuid-1", "sub": "cust_9b21", "client_id": "vendor-claude"})


def test_customer_client_revocation_without_jti() -> None:
    """Customer+client revocation works even when jti is absent."""
    rev = _make_revocation()
    rev.revoke_customer_client(customer_ref="cust_7f3a", client_id="vendor-claude")

    assert rev.is_revoked({"sub": "cust_7f3a", "client_id": "vendor-claude"})
    assert not rev.is_revoked({"sub": "cust_7f3a", "client_id": "vendor-chatgpt"})


# --- Per-client kill switch (ZT-7, least specific) ---


def test_kill_switch_rejects_all_tokens_from_client() -> None:
    """Kill switch rejects every token with the killed client_id."""
    rev = _make_revocation()
    rev.kill_switch(client_id="vendor-claude")

    # Any customer, any jti → revoked
    assert rev.is_revoked({"jti": "uuid-1", "sub": "cust_7f3a", "client_id": "vendor-claude"})
    assert rev.is_revoked({"jti": "uuid-2", "sub": "cust_9b21", "client_id": "vendor-claude"})
    assert rev.is_revoked({"sub": "cust_7f3a", "client_id": "vendor-claude"})
    # Different client → not revoked
    assert not rev.is_revoked({"jti": "uuid-1", "sub": "cust_7f3a", "client_id": "vendor-chatgpt"})


def test_kill_switch_no_customer_or_jti_required() -> None:
    """Kill switch works even when customer and jti are absent."""
    rev = _make_revocation()
    rev.kill_switch(client_id="vendor-claude")

    assert rev.is_revoked({"client_id": "vendor-claude"})
    assert not rev.is_revoked({"client_id": "vendor-chatgpt"})


# --- Scope isolation: revoking one scope doesn't affect others ---


def test_session_revocation_does_not_affect_other_sessions() -> None:
    """Revoking session A does not revoke session B (even same customer+client)."""
    rev = _make_revocation()
    rev.revoke_session(jti="uuid-a", customer_ref="cust_7f3a", client_id="vendor-claude")

    # Session A → revoked
    assert rev.is_revoked({"jti": "uuid-a", "sub": "cust_7f3a", "client_id": "vendor-claude"})
    # Session B (same customer+client) → NOT revoked
    assert not rev.is_revoked({"jti": "uuid-b", "sub": "cust_7f3a", "client_id": "vendor-claude"})


def test_customer_client_revocation_does_not_affect_different_clients() -> None:
    """Revoking customer+client A does not affect customer+client B."""
    rev = _make_revocation()
    rev.revoke_customer_client(customer_ref="cust_7f3a", client_id="vendor-claude")

    assert rev.is_revoked({"jti": "uuid-1", "sub": "cust_7f3a", "client_id": "vendor-claude"})
    assert not rev.is_revoked({"jti": "uuid-1", "sub": "cust_7f3a", "client_id": "vendor-chatgpt"})


def test_kill_switch_does_not_affect_different_clients() -> None:
    """Kill switch for client A does not affect client B."""
    rev = _make_revocation()
    rev.kill_switch(client_id="vendor-claude")

    assert rev.is_revoked({"jti": "uuid-1", "sub": "cust_7f3a", "client_id": "vendor-claude"})
    assert not rev.is_revoked({"jti": "uuid-1", "sub": "cust_7f3a", "client_id": "vendor-chatgpt"})


# --- Combined revocation: multiple scopes active simultaneously ---


def test_multiple_scopes_all_checked() -> None:
    """When multiple scopes are active, any match revokes the token."""
    rev = _make_revocation()
    # Kill switch for vendor-claude
    rev.kill_switch(client_id="vendor-claude")
    # Session revocation for uuid-exact (shouldn't matter — kill switch already covers it)
    rev.revoke_session(jti="uuid-exact", customer_ref="cust_7f3a")
    # Customer+client for cust_9b21 + vendor-chatgpt
    rev.revoke_customer_client(customer_ref="cust_9b21", client_id="vendor-chatgpt")

    # Kill switch match
    assert rev.is_revoked({"jti": "uuid-1", "sub": "cust_7f3a", "client_id": "vendor-claude"})
    # Customer+client match (different client from kill switch)
    assert rev.is_revoked({"jti": "uuid-2", "sub": "cust_9b21", "client_id": "vendor-chatgpt"})
    # No match → not revoked
    assert not rev.is_revoked({"jti": "uuid-3", "sub": "cust_7f3a", "client_id": "vendor-chatgpt"})


def test_session_revocation_catches_token_under_kill_switch() -> None:
    """A session under a killed client is caught by both checks."""
    rev = _make_revocation()
    rev.kill_switch(client_id="vendor-claude")
    rev.revoke_session(jti="uuid-1", customer_ref="cust_7f3a", client_id="vendor-claude")

    # Both scopes match → still just revoked (idempotent)
    assert rev.is_revoked({"jti": "uuid-1", "sub": "cust_7f3a", "client_id": "vendor-claude"})


# --- No false positives ---


def test_no_revocation_when_list_empty() -> None:
    """An empty revocation list never rejects tokens."""
    rev = _make_revocation()

    assert not rev.is_revoked({"jti": "uuid-1", "sub": "cust_7f3a", "client_id": "vendor-claude"})
    assert not rev.is_revoked({"sub": "cust_7f3a", "client_id": "vendor-claude"})
    assert not rev.is_revoked({"jti": "uuid-1", "sub": "cust_7f3a"})
    assert not rev.is_revoked({"client_id": "vendor-claude"})


def test_no_false_positive_different_jti() -> None:
    """Different jti values never collide."""
    rev = _make_revocation()
    rev.revoke_session(jti="uuid-a")

    assert not rev.is_revoked({"jti": "uuid-b"})
    assert not rev.is_revoked({"jti": "uuid-a-1"})
    assert not rev.is_revoked({"jti": "x" * 100})


def test_no_false_positive_different_client_id() -> None:
    """Different client_ids never collide."""
    rev = _make_revocation()
    rev.kill_switch(client_id="vendor-a")

    assert not rev.is_revoked({"client_id": "vendor-b"})
    assert not rev.is_revoked({"client_id": "vendor-a-backup"})


# --- Entry helpers ---


def test_entry_count_tracks_additions() -> None:
    """entry_count reflects the number of revocation entries."""
    rev = _make_revocation()
    assert rev.entry_count == 0

    rev.revoke_session(jti="uuid-1")
    assert rev.entry_count == 1

    rev.revoke_customer_client(customer_ref="cust_7f3a", client_id="vendor-claude")
    assert rev.entry_count == 2

    rev.kill_switch(client_id="vendor-chatgpt")
    assert rev.entry_count == 3


def test_clear_removes_all_entries() -> None:
    """clear() removes all revocation entries."""
    rev = _make_revocation()
    rev.revoke_session(jti="uuid-1")
    rev.kill_switch(client_id="vendor-claude")

    assert rev.entry_count == 2
    rev.clear()
    assert rev.entry_count == 0


def test_get_entries_by_scope_counts_correctly() -> None:
    """get_entries_by_scope returns correct counts per scope type."""
    rev = _make_revocation()

    # Add one of each scope
    rev.revoke_session(jti="uuid-1", customer_ref="cust_7f3a")
    rev.revoke_customer_client(customer_ref="cust_9b21", client_id="vendor-claude")
    rev.kill_switch(client_id="vendor-chatgpt")

    scopes = rev.get_entries_by_scope()
    assert scopes["session"] == 1
    assert scopes["customer_client"] == 1
    assert scopes["kill_switch"] == 1


def test_get_entries_by_scope_empty() -> None:
    """get_entries_by_scope returns zeros for an empty list."""
    rev = _make_revocation()
    assert rev.get_entries_by_scope() == {"session": 0, "customer_client": 0, "kill_switch": 0}


# --- RevocationEntry immutability ---


def test_revocation_entry_is_immutable() -> None:
    """RevocationEntry is a frozen dataclass — no mutation after creation."""
    import dataclasses

    entry = RevocationEntry(jti="uuid-1", customer_ref="cust_7f3a", client_id="vendor-claude")
    with pytest.raises(dataclasses.FrozenInstanceError):
        entry.jti = "hacked"  # type: ignore[misc]


# --- RevocationEntry scope properties ---


def test_is_session_true_when_jti_present() -> None:
    entry = RevocationEntry(jti="uuid-1")
    assert entry.is_session is True
    assert entry.is_customer_client is False
    assert entry.is_kill_switch is False


def test_is_customer_client_true_when_no_jti_has_customer_and_client() -> None:
    entry = RevocationEntry(customer_ref="cust_7f3a", client_id="vendor-claude")
    assert entry.is_session is False
    assert entry.is_customer_client is True
    assert entry.is_kill_switch is False


def test_is_kill_switch_true_when_no_jti_no_customer_has_client() -> None:
    entry = RevocationEntry(client_id="vendor-claude")
    assert entry.is_session is False
    assert entry.is_customer_client is False
    assert entry.is_kill_switch is True


def test_all_false_when_no_fields_set() -> None:
    entry = RevocationEntry()
    assert entry.is_session is False
    assert entry.is_customer_client is False
    assert entry.is_kill_switch is False

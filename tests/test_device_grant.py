"""RFC 8628 device authorization grant — full lifecycle tests.

Covers:
- Device code generation (device_code, user_code, QR data).
- In-memory store basics (create, get, revoke), including the
  ``customer_ref`` field added for audit finding C-01. The pairing half of the
  store -- lookups, ``claim_scan``, ``approve_scanned`` -- is in
  ``tests/test_device_code_pairing_store.py``.
- Device authorization endpoint (``POST /device_authorization``) — public,
  no bearer: the browser holds no credential (RFC 8628's entire premise).
- Token exchange with the ``device_code`` grant type (pending, approved,
  expired, slow_down) — public, no bearer, and never returns a write token
  (audit finding C-01). Since 2026-09-30 it returns no token at all: an
  approved code gets a 503 because issuance is disabled pending the layer-1
  session token, and the code is not spent.
- Mobile app approval callback (``POST /approve``) — requires a verified
  banking-app bearer assertion (``services/confirm/auth.py``); the customer
  comes from the verified ``sub`` and from nowhere else. A request body can
  no longer name a customer at all.
- The uniform-401 property: every way authentication can fail produces one
  identical response body, so an attacker cannot learn which check failed.
- ``POST /approve`` by ``user_code`` only, after a scan: accepted forms of
  the code, the refusal of a code nobody scanned, and the one identical
  ``invalid_grant`` body. ``tests/test_pairing_audit.py`` holds the audit
  ``detail`` each refusal is recorded under.
- Error cases (invalid_request, invalid_grant, invalid_subject, slow_down,
  expired_token, invalid_state).

Until 2026-09-22 ``services/confirm`` authenticated nobody: ``POST /approve``
took the customer from a ``subject_value`` field in its own request body, and
``POST /token`` returned a WRITE-signed token. Three unauthenticated calls
were sufficient to mint ``aud=payments.svc scope=payments:execute`` for any
customer named in a JSON body. That is audit finding C-01, and
``TestAuditFindingC01SubjectValueInBodyIsIgnored`` below drives the exact
three-call chain the audit walked.
"""

from __future__ import annotations

import asyncio
import dataclasses
import inspect
import json
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx2
import pytest
from fastmcp.server.auth.providers.jwt import JWTVerifier, RSAKeyPair
from postern_core.auth.device_codes import (
    DeviceCode,
    DeviceCodeStoreBase,
    InMemoryDeviceCodeStore,
    RedisDeviceCodeStore,
    _device_code_to_dict,
    _generate_device_code,
    _generate_user_code,
)
from postern_core.auth.device_keys import no_enrolled_devices
from postern_core.auth.revocation import RevocationStoreUnavailable
from starlette.applications import Starlette
from starlette.requests import Request

from services.confirm.auth import ASSERTION_STATE_KEY, AppAssertion
from services.confirm.device_auth import approve_callback
from services.confirm.main import create_confirm_app
from services.confirm.settings import MIN_DEVICE_CODE_TTL_SECONDS, ConfirmSettings
from tests.device_grant_helpers import (
    ISSUANCE_DISABLED_BODY,
    jwt_shaped_strings,
    scan_in_store,
)

# Imported for its VALUE, not to run it: `SHORTEST_STORED_TTL` is where the
# truncation that bug B1 rides on was measured, and the floor's derivation
# cites it. Reading it here rather than restating the number is what keeps
# `TestTheFloorIsDerivedAndNotPicked` from becoming a second, drifting copy.
from tests.test_redis_backed_stores import SHORTEST_STORED_TTL

# ---------------------------------------------------------------------------
# Fixtures and helpers.
# ---------------------------------------------------------------------------

#: The banking app's own backend issuer/audience, as `services/confirm/auth.py`
#: verifies them. Distinct from `services/api`'s customer-token audience on
#: purpose -- CLAUDE.md: a token good enough to read a balance must not be
#: good enough to approve a payment.
ISSUER = "https://app.test.invalid"
AUDIENCE = "postern-confirm"


@pytest.fixture(scope="module")
def key_pair() -> RSAKeyPair:
    """The banking app's assertion signing key. Module-scoped: RSA generation
    is slow and every test in this file that needs a *valid* assertion can
    share one key; tests that need a *different* key use `other_key_pair`."""
    return RSAKeyPair.generate()


@pytest.fixture(scope="module")
def other_key_pair() -> RSAKeyPair:
    """A second, unrelated key -- for the "signed by the wrong key" case."""
    return RSAKeyPair.generate()


@pytest.fixture(autouse=True)
def _a_reachable_database(pg_url: str) -> None:
    """Every app in this file needs Postgres, as of 2026-09-26.

    ``POST /approve`` writes one ``audit_log`` row per pairing attempt and
    fails closed if it cannot, so an app pointed at the field default of
    ``localhost:5432`` answers 500 to every request this file makes.
    ``tests/conftest.py``'s session-scoped ``pg_url`` starts the container and
    exports ``POSTERN_DATABASE_URL``; ``ConfirmSettings.for_testing`` reads
    that variable, so depending on the fixture is all this file has to do.

    Autouse rather than a parameter on each app builder: several of the
    ``create_confirm_app`` calls here are inside test methods, and threading a
    URL down to each would touch more lines than the behaviour being tested.
    """


@pytest.fixture()
def store() -> InMemoryDeviceCodeStore:
    return InMemoryDeviceCodeStore()


@pytest.fixture()
def app(key_pair: RSAKeyPair) -> Starlette:
    """The real composition root, with the app-assertion verifier overridden.

    `create_confirm_app` is what wires `AppAssertionMiddleware` in front of
    every route except `PUBLIC_PATHS` (`services/confirm/auth.py`); building
    the test app any other way would test a fixture's opinion of the wiring
    instead of the wiring itself.
    """
    verifier = JWTVerifier(public_key=key_pair.public_key, issuer=ISSUER, audience=AUDIENCE)
    return create_confirm_app(
        ConfirmSettings.for_testing(),
        assertion_verifier=verifier,
        # Nothing in this module approves a challenge; the device GRANT is a
        # different flow from the device SIGNATURE (`postern_core.auth.
        # device_keys` says why they are not the same store), and
        # `create_confirm_app` now refuses to build without one.
        device_key_store=no_enrolled_devices(),
    )


def bearer(
    key_pair: RSAKeyPair,
    subject: str = "cust_7f3a",
    *,
    issuer: str = ISSUER,
    audience: str = AUDIENCE,
    expires_in_seconds: int = 3600,
) -> dict[str, str]:
    """An ``Authorization: Bearer`` header carrying a token signed by ``key_pair``."""
    token = key_pair.create_token(
        subject=subject,
        issuer=issuer,
        audience=audience,
        expires_in_seconds=expires_in_seconds,
    )
    return {"Authorization": f"Bearer {token}"}


def _client(app: Starlette) -> httpx2.AsyncClient:
    """One ASGI-transport client per test. ``httpx2``, never ``httpx`` --
    ``respx`` cannot mock this client at all (CLAUDE.md's version traps)."""
    return httpx2.AsyncClient(transport=httpx2.ASGITransport(app=app), base_url="http://test")


async def _start_device_grant(
    client: httpx2.AsyncClient, client_id: str = "browser-1"
) -> dict[str, Any]:
    """``POST /device_authorization`` and return the parsed body."""
    resp = await client.post("/device_authorization", json={"client_id": client_id})
    assert resp.status_code == 200
    body: dict[str, Any] = resp.json()
    return body


async def _approve(
    app: Starlette,
    client: httpx2.AsyncClient,
    device: dict[str, Any],
    headers: dict[str, str] | None,
    *,
    user_code: str | None = None,
    scanned_by: str | None = "cust_7f3a",
) -> httpx2.Response:
    """Scan ``device`` in the store as ``scanned_by``, then ``POST /approve``.

    ``scanned_by`` must name the customer the bearer names, because
    ``approve_scanned`` approves only for the customer who scanned; the
    default is ``bearer``'s own default subject. ``None`` skips the scan, for
    the requests refused before the pairing is looked up (every 401, and
    ``invalid_subject``). ``user_code`` overrides the value sent, for the
    accepted-forms tests; the scan always uses the code the grant issued.
    """
    if scanned_by is not None:
        await scan_in_store(app, device["user_code"], scanned_by)
    return await client.post(
        "/approve",
        json={"user_code": user_code if user_code is not None else device["user_code"]},
        headers=headers or {},
    )


# ---------------------------------------------------------------------------
# Device code generation.
# ---------------------------------------------------------------------------


class TestDeviceCodeGeneration:
    """RFC 8628 §3.1 — device_code and user_code properties."""

    def test_device_code_is_40_plus_chars(self) -> None:
        """device_code must be at least 40 characters (RFC 8628 §3.1)."""
        for _ in range(10):
            code = _generate_device_code()
            assert len(code) >= 40, f"device_code too short: {len(code)}"

    def test_user_code_is_6_chars_uppercase_alphanumeric(self) -> None:
        """user_code must be 6 uppercase alphanumeric chars, no ambiguous."""
        for _ in range(20):
            code = _generate_user_code()
            assert len(code) == 6
            assert code.isalnum()
            # NOT `code.isupper()`, which is False for a code that happens to
            # be all digits because such a string has no cased characters at
            # all. The alphabet below is 8 digits of 32, so P(all six digits)
            # is 1/4096 and this loop draws 20: a 0.49% failure per run, about
            # one `make ci` in 205. Observed on 26 September 2026 against
            # '849463'. `code == code.upper()` is the assertion that actually
            # means "carries no lowercase" for every string.
            assert code == code.upper()
            # No ambiguous characters (0, O, 1, I, l).
            assert set(code) <= set("23456789ABCDEFGHJKLMNPQRSTUVWXYZ")

    def test_user_code_display_format(self) -> None:
        """user_code_display formats as XXX-XXX."""
        dc = DeviceCode(
            device_code="test",
            user_code="ABCDEF",
            verification_uri="https://example.com",
            expires_at=datetime.now(UTC) + timedelta(minutes=15),
        )
        assert dc.user_code_display == "ABC-DEF"

    def test_user_code_display_short(self) -> None:
        """Short user codes fall through to raw value."""
        dc = DeviceCode(
            device_code="test",
            user_code="ABC",
            verification_uri="https://example.com",
            expires_at=datetime.now(UTC) + timedelta(minutes=15),
        )
        assert dc.user_code_display == "ABC"

    def test_verification_uri_complete_with_query(self) -> None:
        """URI with existing query params gets &d=<display handle>."""
        dc = DeviceCode(
            device_code="test",
            user_code="ABCDEF",
            verification_uri="https://example.com/verify?foo=bar",
            expires_at=datetime.now(UTC) + timedelta(minutes=15),
            display_handle="h4ndle",
        )
        assert dc.verification_uri_complete == "https://example.com/verify?foo=bar&d=h4ndle"

    def test_verification_uri_complete_without_query(self) -> None:
        """URI without query params gets ?d=<display handle>, and never the
        ``user_code``: a URL keyed by a 30-bit code is an enumeration oracle."""
        dc = DeviceCode(
            device_code="test",
            user_code="ABCDEF",
            verification_uri="https://example.com/verify",
            expires_at=datetime.now(UTC) + timedelta(minutes=15),
            display_handle="h4ndle",
        )
        assert dc.verification_uri_complete == "https://example.com/verify?d=h4ndle"
        assert "ABCDEF" not in dc.verification_uri_complete

    def test_is_expired_true(self) -> None:
        dc = DeviceCode(
            device_code="test",
            user_code="ABCDEF",
            verification_uri="https://example.com",
            expires_at=datetime.now(UTC) - timedelta(seconds=1),
        )
        assert dc.is_expired is True

    def test_is_expired_false(self) -> None:
        dc = DeviceCode(
            device_code="test",
            user_code="ABCDEF",
            verification_uri="https://example.com",
            expires_at=datetime.now(UTC) + timedelta(minutes=15),
        )
        assert dc.is_expired is False


# ---------------------------------------------------------------------------
# In-memory store.
# ---------------------------------------------------------------------------


class TestInMemoryDeviceCodeStore:
    """Basic CRUD operations on the in-memory store."""

    async def test_create_and_get(self, store: InMemoryDeviceCodeStore) -> None:
        code = await store.create_device_code(
            client_id="test-client",
            scopes="accounts:read",
            verification_uri="https://auth.example.com/verify",
        )
        assert code.device_code is not None
        assert len(code.device_code) >= 40
        assert code.user_code == "ABC-DEF" or len(code.user_code) == 6
        assert code.client_id == "test-client"
        assert code.scopes == "accounts:read"

        found = await store.get_device_code(code.device_code)
        assert found is not None
        assert found.device_code == code.device_code

    async def test_get_nonexistent(self, store: InMemoryDeviceCodeStore) -> None:
        result = await store.get_device_code("nonexistent")
        assert result is None

    async def test_new_device_code_defaults_customer_ref_empty(
        self, store: InMemoryDeviceCodeStore
    ) -> None:
        """The field audit finding C-01 added starts unset: no identity until
        `/approve` writes it."""
        code = await store.create_device_code(
            client_id="test-client",
            scopes="accounts:read",
            verification_uri="https://auth.example.com/verify",
        )
        assert code.customer_ref == ""

    def test_the_store_offers_no_whole_snapshot_write(self) -> None:
        """A snapshot read before a concurrent ``claim_scan`` or
        ``approve_scanned`` and written back after it would silently undo that
        compare-and-set, so neither writer exists on any backend."""
        for cls in (DeviceCodeStoreBase, InMemoryDeviceCodeStore, RedisDeviceCodeStore):
            assert not hasattr(cls, "update_device_code"), cls.__name__
            assert not hasattr(cls, "approve_device_code"), cls.__name__

    async def test_revoke(self, store: InMemoryDeviceCodeStore) -> None:
        code = await store.create_device_code(
            client_id="test-client",
            scopes="accounts:read",
            verification_uri="https://auth.example.com/verify",
        )
        await store.revoke_device_code(code.device_code)
        assert await store.get_device_code(code.device_code) is None

    async def test_revoke_nonexistent(self, store: InMemoryDeviceCodeStore) -> None:
        # Should not raise.
        await store.revoke_device_code("nonexistent")


# ---------------------------------------------------------------------------
# Device authorization endpoint.
# ---------------------------------------------------------------------------


class TestDeviceAuthorizationEndpoint:
    """POST /device_authorization — generates device codes. Public; see
    TestPublicPathsStayPublic below for the dedicated "no bearer" pin."""

    async def test_returns_device_code_fields(self, app: Starlette) -> None:
        async with _client(app) as client:
            resp = await client.post(
                "/device_authorization",
                json={"client_id": "my-client", "scopes": "accounts:read"},
            )

        assert resp.status_code == 200
        data = resp.json()
        assert "device_code" in data
        assert len(data["device_code"]) >= 40
        assert "user_code" in data
        assert "-" in data["user_code"]  # XXX-XXX format
        assert "verification_uri" in data
        assert "verification_uri_complete" in data
        assert "expires_in" in data
        assert "interval" in data

    async def test_missing_client_id(self, app: Starlette) -> None:
        async with _client(app) as client:
            resp = await client.post("/device_authorization", json={})

        assert resp.status_code == 400
        assert resp.json()["error"] == "invalid_request"

    async def test_default_scopes_stored(self, app: Starlette) -> None:
        """Default scopes are stored on the device code (not returned per RFC 8628)."""
        store: InMemoryDeviceCodeStore = app.state.device_code_store
        async with _client(app) as client:
            resp = await client.post(
                "/device_authorization",
                json={"client_id": "my-client"},
            )

        assert resp.status_code == 200
        data = resp.json()
        # RFC 8628 §3.2 does not include scopes in the response.
        # Verify scopes are stored on the device code instead.
        dc = await store.get_device_code(data["device_code"])
        assert dc is not None
        # Default scopes from the endpoint.
        assert "accounts:read" in dc.scopes

    async def test_the_complete_uri_carries_the_stored_handle_and_neither_code(
        self, app: Starlette
    ) -> None:
        store: InMemoryDeviceCodeStore = app.state.device_code_store
        async with _client(app) as client:
            data = await _start_device_grant(client)

        code = await store.get_device_code(data["device_code"])
        assert code is not None
        assert data["verification_uri_complete"] == (
            f"{data['verification_uri']}?d={code.display_handle}"
        )
        assert code.user_code not in data["verification_uri_complete"]
        assert data["device_code"] not in data["verification_uri_complete"]
        assert data["user_code"] == code.user_code_display

    async def test_the_creating_address_is_recorded_on_the_code(self, app: Starlette) -> None:
        store: InMemoryDeviceCodeStore = app.state.device_code_store
        async with httpx2.AsyncClient(
            transport=httpx2.ASGITransport(app=app, client=("198.51.100.23", 4444)),
            base_url="http://test",
        ) as client:
            data = await _start_device_grant(client)

        code = await store.get_device_code(data["device_code"])
        assert code is not None
        assert code.creator_ip == "198.51.100.23"


# ---------------------------------------------------------------------------
# Token exchange endpoint.
# ---------------------------------------------------------------------------


class TestTokenExchangeEndpoint:
    """POST /token with grant_type=device_code. Public; see
    TestPublicPathsStayPublic below for the dedicated "no bearer" pin."""

    async def test_missing_device_code(self, app: Starlette) -> None:
        async with _client(app) as client:
            resp = await client.post(
                "/token",
                data={"grant_type": "device_code"},
            )

        assert resp.status_code == 400
        assert resp.json()["error"] == "invalid_request"

    async def test_invalid_device_code(self, app: Starlette) -> None:
        async with _client(app) as client:
            resp = await client.post(
                "/token",
                data={"grant_type": "device_code", "device_code": "nonexistent"},
            )

        assert resp.status_code == 400
        assert resp.json()["error"] == "invalid_grant"

    async def test_authorization_pending(self, app: Starlette) -> None:
        """Device code exists but not yet approved → authorization_pending."""
        store: InMemoryDeviceCodeStore = app.state.device_code_store
        code = await store.create_device_code(
            client_id="test-client",
            scopes="accounts:read",
            verification_uri="https://auth.example.com/verify",
        )

        async with _client(app) as client:
            resp = await client.post(
                "/token",
                data={"grant_type": "device_code", "device_code": code.device_code},
            )

        assert resp.status_code == 400
        assert resp.json()["error"] == "authorization_pending"

    async def test_expired_device_code(self, app: Starlette) -> None:
        """Expired device code → expired_token + revoked."""
        store: InMemoryDeviceCodeStore = app.state.device_code_store
        code = DeviceCode(
            device_code="expired-code",
            user_code="ABCDEF",
            verification_uri="https://auth.example.com/verify",
            expires_at=datetime.now(UTC) - timedelta(seconds=1),
        )
        store._codes["expired-code"] = code

        async with _client(app) as client:
            resp = await client.post(
                "/token",
                data={"grant_type": "device_code", "device_code": "expired-code"},
            )

        assert resp.status_code == 400
        assert resp.json()["error"] == "expired_token"
        # Expired codes should be revoked.
        assert await store.get_device_code("expired-code") is None

    async def test_approved_exchange_is_refused_and_the_approval_names_the_bearer_subject(
        self, app: Starlette, key_pair: RSAKeyPair
    ) -> None:
        """`/token` used to read `client_id`, the field a caller of
        `/device_authorization` controls; it now reads `customer_ref`, which
        only a verified `/approve` write ever sets (audit finding C-01).

        Since 2026-09-30 an approved code gets the issuance-disabled 503 and
        no token, so the identity is asserted on the stored code instead of
        on a minted token's `sub`."""
        async with _client(app) as client:
            device = await _start_device_grant(client, client_id="cust_should_be_ignored")
            approve = await _approve(app, client, device, bearer(key_pair, subject="cust_7f3a"))
            assert approve.status_code == 200

            resp = await client.post(
                "/token",
                data={"grant_type": "device_code", "device_code": device["device_code"]},
            )

        assert resp.status_code == 503
        assert resp.json() == ISSUANCE_DISABLED_BODY
        assert jwt_shaped_strings(resp.text) == []

        stored = await app.state.device_code_store.get_device_code(device["device_code"])
        assert stored is not None
        assert stored.customer_ref == "cust_7f3a"
        assert stored.exchanged_at is None

    async def test_approved_with_empty_customer_ref_is_invalid_state(self, app: Starlette) -> None:
        """A code that reads as approved with no identity attached must mint
        nothing. `/approve` writes `approved` and `customer_ref` together in
        one store call, so this state should not occur outside a corrupted
        store, and `/token` must refuse it rather than guess."""
        store: InMemoryDeviceCodeStore = app.state.device_code_store
        code = DeviceCode(
            device_code="no-customer-ref",
            user_code="ABCDEF",
            verification_uri="https://auth.example.com/verify",
            expires_at=datetime.now(UTC) + timedelta(minutes=15),
            approved=True,
            approved_at=datetime.now(UTC),
            customer_ref="",
        )
        store._codes["no-customer-ref"] = code

        async with _client(app) as client:
            resp = await client.post(
                "/token",
                data={"grant_type": "device_code", "device_code": "no-customer-ref"},
            )

        assert resp.status_code == 500
        data = resp.json()
        assert data["error"] == "invalid_state"
        assert data["error_description"] == "approval missing customer identity"

    async def test_approved_with_malformed_customer_ref_is_invalid_state(
        self, app: Starlette
    ) -> None:
        """A `customer_ref` that does not match the opaque `cust_...` shape
        -- the operator's app backend minting the wrong claim, not an
        attacker -- gets a distinct refusal, and the raw value is never
        echoed back on the wire."""
        store: InMemoryDeviceCodeStore = app.state.device_code_store
        code = DeviceCode(
            device_code="bad-customer-ref",
            user_code="ABCDEF",
            verification_uri="https://auth.example.com/verify",
            expires_at=datetime.now(UTC) + timedelta(minutes=15),
            approved=True,
            approved_at=datetime.now(UTC),
            customer_ref="ES9121000418450200051332",  # an IBAN shape, not cust_...
        )
        store._codes["bad-customer-ref"] = code

        async with _client(app) as client:
            resp = await client.post(
                "/token",
                data={"grant_type": "device_code", "device_code": "bad-customer-ref"},
            )

        assert resp.status_code == 500
        data = resp.json()
        assert data["error"] == "invalid_state"
        assert data["error_description"] == "approval identity is not a customer reference"
        assert "ES9121000418450200051332" not in resp.text

    async def test_slow_down(self, app: Starlette) -> None:
        """Polling too fast while pending → slow_down."""
        store: InMemoryDeviceCodeStore = app.state.device_code_store
        code = await store.create_device_code(
            client_id="cust_123",
            scopes="accounts:read",
            verification_uri="https://auth.example.com/verify",
        )
        # Do NOT approve — test slow_down in pending state.

        async with _client(app) as client:
            # First poll → authorization_pending (records poll time).
            resp1 = await client.post(
                "/token",
                data={"grant_type": "device_code", "device_code": code.device_code},
            )
        assert resp1.status_code == 400
        assert resp1.json()["error"] == "authorization_pending"

        # Second poll immediately after → slow_down.
        async with _client(app) as client:
            resp2 = await client.post(
                "/token",
                data={"grant_type": "device_code", "device_code": code.device_code},
            )
        assert resp2.status_code == 400
        assert resp2.json()["error"] == "slow_down"

        # After waiting, poll → authorization_pending again (still not approved).
        await asyncio.sleep(6)
        async with _client(app) as client:
            resp3 = await client.post(
                "/token",
                data={"grant_type": "device_code", "device_code": code.device_code},
            )
        assert resp3.status_code == 400
        assert resp3.json()["error"] == "authorization_pending"

    async def test_unknown_device_codes_leave_no_poll_time(self, app: Starlette) -> None:
        """``POST /token`` is public: a code the store does not hold must not
        create an entry in the per-code poll-time map."""
        async with _client(app) as client:
            for i in range(1000):
                resp = await client.post(
                    "/token",
                    data={"grant_type": "device_code", "device_code": f"unknown-{i}"},
                )
                assert resp.status_code in (400, 429)
        assert not getattr(app.state, "_poll_times", {})

    async def test_poll_times_older_than_the_code_ttl_are_dropped(self, app: Starlette) -> None:
        """An entry for a code last polled more than ``device_code_ttl_seconds``
        ago is gone after a later poll of any live code; a recent one stays."""
        store: InMemoryDeviceCodeStore = app.state.device_code_store
        ttl = app.state.settings.device_code_ttl_seconds
        now = datetime.now(UTC)
        app.state._poll_times = {
            "stale": now - timedelta(seconds=ttl + 1),
            "recent": now - timedelta(seconds=ttl - 60),
        }
        code = await store.create_device_code(
            client_id="cust_123",
            scopes="accounts:read",
            verification_uri="https://auth.example.com/verify",
        )
        async with _client(app) as client:
            resp = await client.post(
                "/token",
                data={"grant_type": "device_code", "device_code": code.device_code},
            )
        assert resp.json()["error"] == "authorization_pending"
        assert set(app.state._poll_times) == {"recent", code.device_code}

    async def test_expired_code_drops_its_poll_time(self, app: Starlette) -> None:
        """Once the store reports a code expired, its entry is removed."""
        store: InMemoryDeviceCodeStore = app.state.device_code_store
        code = await store.create_device_code(
            client_id="cust_123",
            scopes="accounts:read",
            verification_uri="https://auth.example.com/verify",
        )
        async with _client(app) as client:
            first = await client.post(
                "/token",
                data={"grant_type": "device_code", "device_code": code.device_code},
            )
            assert first.json()["error"] == "authorization_pending"
            assert code.device_code in app.state._poll_times
            store._codes[code.device_code] = dataclasses.replace(
                code, expires_at=datetime.now(UTC) - timedelta(seconds=1)
            )
            second = await client.post(
                "/token",
                data={"grant_type": "device_code", "device_code": code.device_code},
            )
        assert second.json()["error"] == "expired_token"
        assert code.device_code not in app.state._poll_times


# ---------------------------------------------------------------------------
# Approval callback.
# ---------------------------------------------------------------------------


class TestApproveCallback:
    """POST /approve — mobile app approval. Requires a verified bearer
    assertion (see TestApproveCallbackUniform401 below); the customer comes
    from its `sub`, never from the body (audit finding C-01), and the code must
    have been scanned by that same customer first."""

    async def test_approve_success_takes_the_customer_from_the_bearer(
        self, app: Starlette, key_pair: RSAKeyPair
    ) -> None:
        store: InMemoryDeviceCodeStore = app.state.device_code_store
        code = await store.create_device_code(
            client_id="original-client",
            scopes="accounts:read",
            verification_uri="https://auth.example.com/verify",
        )
        await scan_in_store(app, code.user_code, "cust_123")

        async with _client(app) as client:
            resp = await client.post(
                "/approve",
                json={"user_code": code.user_code_display},
                headers=bearer(key_pair, subject="cust_123"),
            )

        assert resp.status_code == 200
        assert resp.json()["status"] == "approved"

        # Verify the code is now approved with the bearer's subject, not
        # anything from the body.
        updated = await store.get_device_code(code.device_code)
        assert updated is not None
        assert updated.approved is True
        assert updated.customer_ref == "cust_123"
        # client_id is untouched -- it stopped being an identity field.
        assert updated.client_id == "original-client"

    async def test_approve_missing_fields_with_a_valid_bearer_is_400(
        self, app: Starlette, key_pair: RSAKeyPair
    ) -> None:
        async with _client(app) as client:
            resp = await client.post("/approve", json={}, headers=bearer(key_pair))

        assert resp.status_code == 400
        assert resp.json()["error"] == "invalid_request"

    async def test_approve_nonexistent_code(self, app: Starlette, key_pair: RSAKeyPair) -> None:
        async with _client(app) as client:
            resp = await client.post(
                "/approve",
                json={"user_code": "ABCDEF"},
                headers=bearer(key_pair),
            )

        assert resp.status_code == 400
        assert resp.json()["error"] == "invalid_grant"

    async def test_a_second_customer_cannot_approve_a_code_the_first_scanned(
        self, app: Starlette, key_pair: RSAKeyPair
    ) -> None:
        """The swap the old ``already_approved`` check guarded against, now
        impossible by construction: ``approve_scanned`` approves only for the
        customer in ``scanned_by``."""
        store: InMemoryDeviceCodeStore = app.state.device_code_store
        code = await store.create_device_code(
            client_id="test-client",
            scopes="accounts:read",
            verification_uri="https://auth.example.com/verify",
        )
        await scan_in_store(app, code.user_code, "cust_123")

        async with _client(app) as client:
            first = await client.post(
                "/approve",
                json={"user_code": code.user_code_display},
                headers=bearer(key_pair, subject="cust_123"),
            )
            assert first.status_code == 200

            second = await client.post(
                "/approve",
                json={"user_code": code.user_code_display},
                headers=bearer(key_pair, subject="cust_attacker"),
            )

        assert second.status_code == 400
        assert second.json()["error"] == "invalid_grant"
        updated = await store.get_device_code(code.device_code)
        assert updated is not None
        assert updated.customer_ref == "cust_123"

    async def test_an_unscanned_code_is_refused_and_not_approved(
        self, app: Starlette, key_pair: RSAKeyPair
    ) -> None:
        """Knowing a ``user_code`` approves nothing: the same customer must
        have scanned the QR with a current rotation token first."""
        store: InMemoryDeviceCodeStore = app.state.device_code_store
        code = await store.create_device_code(
            client_id="test-client",
            scopes="accounts:read",
            verification_uri="https://auth.example.com/verify",
        )

        async with _client(app) as client:
            resp = await client.post(
                "/approve",
                json={"user_code": code.user_code_display},
                headers=bearer(key_pair),
            )

        assert resp.status_code == 400
        assert resp.json()["error"] == "invalid_grant"
        updated = await store.get_device_code(code.device_code)
        assert updated is not None
        assert updated.approved is False

    async def test_every_pairing_refusal_answers_the_identical_body(
        self, app: Starlette, key_pair: RSAKeyPair
    ) -> None:
        """Unknown, unscanned, scanned by another and already approved: one
        body, so a caller learns nothing about whether a pairing exists."""
        store: InMemoryDeviceCodeStore = app.state.device_code_store
        unscanned = await store.create_device_code(
            client_id="c", scopes="accounts:read", verification_uri="https://a.test/v"
        )
        someone_elses = await store.create_device_code(
            client_id="c", scopes="accounts:read", verification_uri="https://a.test/v"
        )
        await scan_in_store(app, someone_elses.user_code, "cust_9e21")
        approved = await store.create_device_code(
            client_id="c", scopes="accounts:read", verification_uri="https://a.test/v"
        )
        await scan_in_store(app, approved.user_code, "cust_7f3a")
        assert await store.approve_scanned(approved.device_code, "cust_7f3a") is True

        bodies = []
        async with _client(app) as client:
            for user_code in ("ZZZ-ZZZ", unscanned.user_code, someone_elses.user_code):
                resp = await client.post(
                    "/approve", json={"user_code": user_code}, headers=bearer(key_pair)
                )
                assert resp.status_code == 400
                bodies.append(resp.json())
            resp = await client.post(
                "/approve", json={"user_code": approved.user_code}, headers=bearer(key_pair)
            )
            assert resp.status_code == 400
            bodies.append(resp.json())

        assert all(body == bodies[0] for body in bodies), bodies
        assert bodies[0]["error"] == "invalid_grant"

    async def test_a_body_still_carrying_device_code_is_refused_loudly(
        self, app: Starlette, key_pair: RSAKeyPair
    ) -> None:
        """An app on the old contract fails with ``invalid_request``, never
        with a pairing refusal it could mistake for a wrong code."""
        store: InMemoryDeviceCodeStore = app.state.device_code_store
        code = await store.create_device_code(
            client_id="c", scopes="accounts:read", verification_uri="https://a.test/v"
        )
        await scan_in_store(app, code.user_code, "cust_7f3a")
        legacy = dict(device_code=code.device_code, user_code=code.user_code_display)

        async with _client(app) as client:
            resp = await client.post("/approve", json=legacy, headers=bearer(key_pair))

        assert resp.status_code == 400
        assert resp.json()["error"] == "invalid_request"
        stored = await store.get_device_code(code.device_code)
        assert stored is not None and stored.approved is False


# ---------------------------------------------------------------------------
# Full lifecycle: device auth → approval → token exchange.
# ---------------------------------------------------------------------------


class TestFullLifecycle:
    """End-to-end device authorization flow."""

    async def test_complete_flow(self, app: Starlette, key_pair: RSAKeyPair) -> None:
        """Device code creation → approval (with a verified bearer) → token
        exchange, yielding a read token only."""
        async with _client(app) as client:
            # Step 1: Request device code.
            resp = await client.post(
                "/device_authorization",
                json={"client_id": "claude-code", "scopes": "accounts:read transactions:read"},
            )
            assert resp.status_code == 200
            device_data = resp.json()
            device_code_value = device_data["device_code"]

            # Step 2: Poll token before approval → authorization_pending.
            resp = await client.post(
                "/token",
                data={
                    "grant_type": "device_code",
                    "device_code": device_code_value,
                },
            )
            assert resp.status_code == 400
            assert resp.json()["error"] == "authorization_pending"

            # Step 3: Mobile app scans (through the store here; POST /scan has
            # its own tests) and approves, with a verified assertion and the
            # pairing code from the QR.
            await scan_in_store(app, device_data["user_code"], "cust_abc")
            resp = await client.post(
                "/approve",
                json={"user_code": device_data["user_code"]},
                headers=bearer(key_pair, subject="cust_abc"),
            )
            assert resp.status_code == 200

            # Step 4: Poll token after approval → the issuance-disabled 503,
            # and no token of any kind in the body.
            resp = await client.post(
                "/token",
                data={
                    "grant_type": "device_code",
                    "device_code": device_code_value,
                },
            )
            assert resp.status_code == 503
            assert resp.json() == ISSUANCE_DISABLED_BODY
            assert jwt_shaped_strings(resp.text) == []

    async def test_expired_then_new_code(self, app: Starlette) -> None:
        """Expired code is rejected; a new code works."""
        store: InMemoryDeviceCodeStore = app.state.device_code_store

        # Create and expire a code.
        old_code = DeviceCode(
            device_code="old-expired",
            user_code="ABCDEF",
            verification_uri="https://auth.example.com/verify",
            expires_at=datetime.now(UTC) - timedelta(seconds=1),
        )
        store._codes["old-expired"] = old_code

        async with _client(app) as client:
            # Old code → expired_token.
            resp = await client.post(
                "/token",
                data={"grant_type": "device_code", "device_code": "old-expired"},
            )
            assert resp.status_code == 400
            assert resp.json()["error"] == "expired_token"

            # New code → works.
            resp = await client.post(
                "/device_authorization",
                json={"client_id": "new-client"},
            )
            assert resp.status_code == 200
            new_dc = resp.json()["device_code"]
            assert len(new_dc) >= 40


# ---------------------------------------------------------------------------
# Serialization round-trip.
# ---------------------------------------------------------------------------


class TestSerialization:
    """DeviceCode to_dict/from_dict and to_json/from_json."""

    def test_round_trip_dict(self) -> None:
        dc = DeviceCode(
            device_code="test-123",
            user_code="ABCDEF",
            verification_uri="https://auth.example.com/verify",
            expires_at=datetime.now(UTC) + timedelta(minutes=15),
            interval=10,
            client_id="my-client",
            scopes="accounts:read transactions:read",
            approved=True,
            approved_at=datetime.now(UTC),
        )
        d = _device_code_to_dict(dc)
        dc2 = DeviceCode.from_dict(d)
        assert dc2.device_code == dc.device_code
        assert dc2.user_code == dc.user_code
        assert dc2.client_id == dc.client_id
        assert dc2.scopes == dc.scopes
        assert dc2.approved is True

    def test_round_trip_json(self) -> None:
        dc = DeviceCode(
            device_code="json-test",
            user_code="XYZ123",
            verification_uri="https://auth.example.com/verify?foo=bar",
            expires_at=datetime.now(UTC) + timedelta(minutes=30),
            interval=5,
            client_id="json-client",
            scopes="cards:read",
            approved=False,
        )
        j = dc.to_json()
        dc2 = DeviceCode.from_json(j)
        assert dc2.device_code == dc.device_code
        assert dc2.user_code_display == dc.user_code_display
        assert dc2.verification_uri_complete == dc.verification_uri_complete
        assert dc2.approved is False

    def test_round_trip_with_null_approved_at(self) -> None:
        """Unapproved codes have approved_at=None, which serializes correctly."""
        dc = DeviceCode(
            device_code="no-approve",
            user_code="AAAAAA",
            verification_uri="https://example.com",
            expires_at=datetime.now(UTC) + timedelta(minutes=15),
            approved=False,
            approved_at=None,
        )
        j = dc.to_json()
        dc2 = DeviceCode.from_json(j)
        assert dc2.approved is False
        assert dc2.approved_at is None

    def test_customer_ref_round_trips_through_json(self) -> None:
        dc = DeviceCode(
            device_code="cref-json",
            user_code="ABCDEF",
            verification_uri="https://auth.example.com/verify",
            expires_at=datetime.now(UTC) + timedelta(minutes=15),
            approved=True,
            approved_at=datetime.now(UTC),
            customer_ref="cust_7f3a",
        )
        dc2 = DeviceCode.from_json(dc.to_json())
        assert dc2.customer_ref == "cust_7f3a"

    def test_customer_ref_round_trips_through_dict(self) -> None:
        dc = DeviceCode(
            device_code="cref-dict",
            user_code="ABCDEF",
            verification_uri="https://auth.example.com/verify",
            expires_at=datetime.now(UTC) + timedelta(minutes=15),
            customer_ref="cust_9999",
        )
        dc2 = DeviceCode.from_dict(_device_code_to_dict(dc))
        assert dc2.customer_ref == "cust_9999"

    def test_from_dict_without_the_new_fields_defaults_customer_ref(self) -> None:
        """A Redis-backed store can hold codes serialized by a previous
        release. `.get()` defaults, not `data[...]`, keep an old record
        deserializing instead of raising `KeyError` on every in-flight
        device grant when this rolls out -- and defaulting to empty is the
        fail-closed direction: `/token` then refuses the code instead of
        minting from a stale identity. A ``user_code_attempts`` key, which
        records written before 2026-09-30 carry, is ignored."""
        legacy: dict[str, Any] = {
            "device_code": "legacy",
            "user_code": "ABCDEF",
            "verification_uri": "https://auth.example.com/verify",
            "expires_at": (datetime.now(UTC) + timedelta(minutes=15)).timestamp(),
            "interval": 5,
            "client_id": "legacy-client",
            "scopes": "accounts:read",
            "approved": False,
            "approved_at": None,
            "user_code_attempts": 2,
            # No "customer_ref" key at all.
        }
        dc = DeviceCode.from_dict(legacy)
        assert dc.customer_ref == ""
        assert not hasattr(dc, "user_code_attempts")

    def test_exchanged_at_round_trips_through_json(self) -> None:
        """The field a replay is refused on has to survive a Redis round trip.

        Without it in both directions the two backends disagree on whether a
        code is spent, and the one that forgets hands out a second token.
        """
        spent_at = datetime.now(UTC)
        dc = DeviceCode(
            device_code="spent-json",
            user_code="ABCDEF",
            verification_uri="https://auth.example.com/verify",
            expires_at=datetime.now(UTC) + timedelta(minutes=15),
            approved=True,
            approved_at=datetime.now(UTC),
            customer_ref="cust_7f3a",
            exchanged_at=spent_at,
        )

        dc2 = DeviceCode.from_json(dc.to_json())

        assert dc2.exchanged_at is not None
        assert abs((dc2.exchanged_at - spent_at).total_seconds()) < 0.001

    def test_from_dict_without_exchanged_at_reads_as_unspent(self) -> None:
        """A `.get` default, for the reason ``customer_ref`` has one.

        The direction is the opposite of ``customer_ref``'s and deliberately
        so: a code serialized by the previous release was written by a build
        that could not spend one, so "unspent" is the true reading of its
        absence rather than a fail-closed guess. What it costs is bounded by
        the code's own 900-second life.
        """
        legacy: dict[str, Any] = {
            "device_code": "legacy-unspent",
            "user_code": "ABCDEF",
            "verification_uri": "https://auth.example.com/verify",
            "expires_at": (datetime.now(UTC) + timedelta(minutes=15)).timestamp(),
            "approved": True,
            "approved_at": datetime.now(UTC).timestamp(),
            "customer_ref": "cust_7f3a",
            # No "exchanged_at" key at all.
        }

        assert DeviceCode.from_dict(legacy).exchanged_at is None


# ---------------------------------------------------------------------------
# Endpoint wiring — JSON vs form body, content-type handling.
# ---------------------------------------------------------------------------


class TestDeviceAuthorizationContentType:
    """device_authorization accepts both JSON and form bodies."""

    async def test_json_body_accepted(self, app: Starlette) -> None:
        """JSON body with client_id works."""
        async with _client(app) as c:
            resp = await c.post(
                "/device_authorization",
                json={"client_id": "test_client"},
                headers={"content-type": "application/json"},
            )
        assert resp.status_code == 200
        data = resp.json()
        assert "device_code" in data
        assert "user_code" in data

    async def test_form_body_accepted(self, app: Starlette) -> None:
        """Form body with client_id works."""
        async with _client(app) as c:
            resp = await c.post(
                "/device_authorization",
                data={"client_id": "test_client"},
            )
        assert resp.status_code == 200
        data = resp.json()
        assert "device_code" in data

    async def test_missing_client_id_returns_400(self, app: Starlette) -> None:
        """No client_id → 400."""
        async with _client(app) as c:
            resp = await c.post(
                "/device_authorization",
                json={},
                headers={"content-type": "application/json"},
            )
        assert resp.status_code == 400
        data = resp.json()
        assert data["error"] == "invalid_request"

    async def test_custom_scopes_stored(self, app: Starlette) -> None:
        """Custom scopes are stored in the device code."""
        async with _client(app) as c:
            resp = await c.post(
                "/device_authorization",
                json={"client_id": "test_client", "scopes": "payments:execute"},
                headers={"content-type": "application/json"},
            )
        assert resp.status_code == 200


class TestTokenEndpointGrantTypes:
    """token_endpoint handles different grant types."""

    async def test_device_code_grant_works(self, app: Starlette) -> None:
        """grant_type=device_code is accepted."""
        async with _client(app) as c:
            # First create a device code.
            dc_resp = await c.post(
                "/device_authorization",
                json={"client_id": "test_client"},
                headers={"content-type": "application/json"},
            )
            dc = dc_resp.json()

            # Then try to exchange it (will be pending).
            resp = await c.post(
                "/token",
                data={"grant_type": "device_code", "device_code": dc["device_code"]},
            )
        assert resp.status_code == 400
        data = resp.json()
        assert data["error"] == "authorization_pending"

    async def test_unknown_grant_type_returns_404(self, app: Starlette) -> None:
        """Non-device_code grant type → 404."""
        async with _client(app) as c:
            resp = await c.post(
                "/token",
                data={"grant_type": "authorization_code"},
            )
        assert resp.status_code == 404
        data = resp.json()
        assert data["error"] == "unsupported_grant_type"

    async def test_missing_device_code_returns_400(self, app: Starlette) -> None:
        """No device_code in form → 400."""
        async with _client(app) as c:
            resp = await c.post(
                "/token",
                data={"grant_type": "device_code"},
            )
        assert resp.status_code == 400
        data = resp.json()
        assert data["error"] == "invalid_request"


class TestApproveCallbackEdgeCases:
    """approve_callback edge cases: extra body fields, empty required fields."""

    async def test_extra_body_fields_are_ignored_including_subject_value(
        self, app: Starlette, key_pair: RSAKeyPair
    ) -> None:
        """A body still carrying `subject_value` (the field audit finding
        C-01 removed) or any other extra field has no effect on the minted
        identity, which comes only from the bearer."""
        async with _client(app) as c:
            dc_resp = await c.post(
                "/device_authorization",
                json={"client_id": "test_client"},
                headers={"content-type": "application/json"},
            )
            dc = dc_resp.json()
            await scan_in_store(app, dc["user_code"], "cust_7f3a")

            resp = await c.post(
                "/approve",
                json={
                    "user_code": dc["user_code"],
                    "subject_value": "cust_evil",
                    "approval_signature": "sig_xyz",
                },
                headers=bearer(key_pair, subject="cust_7f3a"),
            )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "approved"

        store: InMemoryDeviceCodeStore = app.state.device_code_store
        updated = await store.get_device_code(dc["device_code"])
        assert updated is not None
        assert updated.customer_ref == "cust_7f3a"

    async def test_approve_empty_user_code(self, app: Starlette, key_pair: RSAKeyPair) -> None:
        """Empty user_code → 400, even with a valid bearer."""
        async with _client(app) as c:
            resp = await c.post(
                "/approve",
                json={"user_code": ""},
                headers=bearer(key_pair),
            )
        assert resp.status_code == 400
        data = resp.json()
        assert data["error"] == "invalid_request"

    async def test_approve_bearer_with_empty_subject_claim_is_401_not_403(
        self, app: Starlette, key_pair: RSAKeyPair
    ) -> None:
        """An empty `sub` fails the middleware's own truthiness check before
        the handler's `CustomerRef` validation ever runs, so this is the
        uniform 401 -- never the 403 `invalid_subject` a non-empty malformed
        subject gets (see TestApproveCallbackInvalidSubjectShape)."""
        async with _client(app) as c:
            resp = await c.post(
                "/approve",
                json={"user_code": "ABCDEF"},
                headers=bearer(key_pair, subject=""),
            )
        assert resp.status_code == 401
        data = resp.json()
        assert data["error"] == "invalid_token"


class TestCompleteFlow:
    """End-to-end device authorization flow."""

    async def test_full_device_code_lifecycle(self, app: Starlette, key_pair: RSAKeyPair) -> None:
        """Create → pending → approve → exchange tokens."""
        async with _client(app) as c:
            # 1. Create device code.
            dc_resp = await c.post(
                "/device_authorization",
                json={"client_id": "test_client"},
                headers={"content-type": "application/json"},
            )
            assert dc_resp.status_code == 200
            dc = dc_resp.json()

            # 2. Poll while pending.
            resp = await c.post(
                "/token",
                data={"grant_type": "device_code", "device_code": dc["device_code"]},
            )
            assert resp.status_code == 400
            assert resp.json()["error"] == "authorization_pending"

            # 3. Scan and approve via mobile app, with a verified assertion and
            # the pairing code.
            await scan_in_store(app, dc["user_code"], "cust_7f3a")
            approve_resp = await c.post(
                "/approve",
                json={"user_code": dc["user_code"]},
                headers=bearer(key_pair, subject="cust_7f3a"),
            )
            assert approve_resp.status_code == 200

            # 4. Poll after approval: issuance is disabled, so no token.
            token_resp = await c.post(
                "/token",
                data={"grant_type": "device_code", "device_code": dc["device_code"]},
            )
        assert token_resp.status_code == 503
        assert token_resp.json() == ISSUANCE_DISABLED_BODY
        assert jwt_shaped_strings(token_resp.text) == []


# ---------------------------------------------------------------------------
# services/confirm/auth.py's PUBLIC_PATHS — pinned so they stay public.
# ---------------------------------------------------------------------------


class TestPublicPathsStayPublic:
    """`/device_authorization` and `/token` hold no credential to present --
    the browser is the caller, by RFC 8628's whole premise, and it never has
    an app assertion. A future change that started requiring a bearer here
    would be a category error per `services/confirm/auth.py`'s
    `PUBLIC_PATHS` docstring; this pins the opposite so it breaks loudly
    instead of silently narrowing the device grant to nothing."""

    async def test_device_authorization_reachable_with_no_authorization_header(
        self, app: Starlette
    ) -> None:
        async with _client(app) as client:
            resp = await client.post("/device_authorization", json={"client_id": "browser-1"})
        assert resp.status_code == 200

    async def test_token_endpoint_reachable_with_no_authorization_header(
        self, app: Starlette
    ) -> None:
        async with _client(app) as client:
            device = await _start_device_grant(client)
            resp = await client.post(
                "/token",
                data={"grant_type": "device_code", "device_code": device["device_code"]},
            )
        # authorization_pending, not 401 -- the request reached the handler
        # rather than being refused by AppAssertionMiddleware.
        assert resp.status_code == 400
        assert resp.json()["error"] == "authorization_pending"


# ---------------------------------------------------------------------------
# The uniform-401 property (audit findings C-01, C-02).
# ---------------------------------------------------------------------------


class TestApproveCallbackUniform401:
    """Every way an assertion can fail to verify must be indistinguishable.

    `services/confirm/auth.py`: "an attacker probing configuration cannot
    separate 'your audience is wrong' from 'your signature is wrong' and
    walk the difference."
    """

    @pytest.fixture()
    async def pending_code(self, app: Starlette) -> dict[str, Any]:
        async with _client(app) as client:
            return await _start_device_grant(client)

    async def test_no_authorization_header(
        self, app: Starlette, pending_code: dict[str, Any]
    ) -> None:
        async with _client(app) as client:
            resp = await _approve(app, client, pending_code, None)
        assert resp.status_code == 401

    async def test_malformed_jwt(self, app: Starlette, pending_code: dict[str, Any]) -> None:
        async with _client(app) as client:
            resp = await _approve(
                app, client, pending_code, {"Authorization": "Bearer not-a-jwt-at-all"}
            )
        assert resp.status_code == 401

    async def test_expired_token(
        self, app: Starlette, pending_code: dict[str, Any], key_pair: RSAKeyPair
    ) -> None:
        async with _client(app) as client:
            resp = await _approve(
                app, client, pending_code, bearer(key_pair, expires_in_seconds=-10)
            )
        assert resp.status_code == 401

    async def test_wrong_issuer(
        self, app: Starlette, pending_code: dict[str, Any], key_pair: RSAKeyPair
    ) -> None:
        async with _client(app) as client:
            resp = await _approve(
                app, client, pending_code, bearer(key_pair, issuer="https://wrong-issuer.invalid")
            )
        assert resp.status_code == 401

    async def test_wrong_audience(
        self, app: Starlette, pending_code: dict[str, Any], key_pair: RSAKeyPair
    ) -> None:
        async with _client(app) as client:
            resp = await _approve(
                app, client, pending_code, bearer(key_pair, audience="wrong-audience")
            )
        assert resp.status_code == 401

    async def test_wrong_signature(
        self, app: Starlette, pending_code: dict[str, Any], other_key_pair: RSAKeyPair
    ) -> None:
        async with _client(app) as client:
            resp = await _approve(app, client, pending_code, bearer(other_key_pair))
        assert resp.status_code == 401

    async def test_empty_subject_claim(
        self, app: Starlette, pending_code: dict[str, Any], key_pair: RSAKeyPair
    ) -> None:
        async with _client(app) as client:
            resp = await _approve(app, client, pending_code, bearer(key_pair, subject=""))
        assert resp.status_code == 401

    async def test_every_failure_mode_returns_the_identical_body(
        self,
        app: Starlette,
        pending_code: dict[str, Any],
        key_pair: RSAKeyPair,
        other_key_pair: RSAKeyPair,
    ) -> None:
        """The caller learns that it is not authenticated and nothing else."""
        variants: list[dict[str, str] | None] = [
            None,
            {"Authorization": "Bearer not-a-jwt-at-all"},
            bearer(key_pair, expires_in_seconds=-10),
            bearer(key_pair, issuer="https://wrong-issuer.invalid"),
            bearer(key_pair, audience="wrong-audience"),
            bearer(other_key_pair),
            bearer(key_pair, subject=""),
        ]
        bodies: list[dict[str, Any]] = []
        async with _client(app) as client:
            for headers in variants:
                resp = await _approve(app, client, pending_code, headers)
                assert resp.status_code == 401
                bodies.append(resp.json())

        assert all(body == bodies[0] for body in bodies), bodies
        assert bodies[0] == {
            "error": "invalid_token",
            "error_description": "a verified app assertion is required",
        }


class TestApproveCallbackInvalidSubjectShape:
    """A verified assertion whose `sub` is not `cust[:_]...` is a distinct
    failure from "not authenticated": the operator's app backend minted the
    wrong claim, not an attacker forging a token."""

    async def test_non_customer_subject_is_403(self, app: Starlette, key_pair: RSAKeyPair) -> None:
        async with _client(app) as client:
            device = await _start_device_grant(client)
            resp = await _approve(app, client, device, bearer(key_pair, subject="not-a-customer"))
        assert resp.status_code == 403
        assert resp.json() == {
            "error": "invalid_subject",
            "error_description": "assertion subject is not a customer reference",
        }


# ---------------------------------------------------------------------------
# Audit finding C-01 — the exploit chain, and what replaces it.
# ---------------------------------------------------------------------------


class TestAuditFindingC01SubjectValueInBodyIsIgnored:
    """C-01: three unauthenticated calls used to be enough to mint a token
    for any customer named in a JSON body. Both halves are gone: `/approve`
    refuses without a verified assertion, and even when one is present, its
    body's `subject_value` has no effect on the minted identity."""

    async def test_the_original_exploit_chain_no_longer_completes(self, app: Starlette) -> None:
        """`/device_authorization(client_id=cust_victim)` → `/approve` with a
        bare `subject_value` naming the victim and no bearer → 401 →
        `/token` still pending. This is the exact three-call chain the audit
        walked."""
        async with _client(app) as client:
            device = await _start_device_grant(client, client_id="cust_victim")

            approve_resp = await client.post(
                "/approve",
                json={"user_code": device["user_code"], "subject_value": "cust_victim"},
            )
            assert approve_resp.status_code == 401
            assert approve_resp.json() == {
                "error": "invalid_token",
                "error_description": "a verified app assertion is required",
            }

            token_resp = await client.post(
                "/token",
                data={"grant_type": "device_code", "device_code": device["device_code"]},
            )
        assert token_resp.status_code == 400
        assert token_resp.json()["error"] == "authorization_pending"

    async def test_a_bearer_subject_wins_over_a_body_subject_value(
        self, app: Starlette, key_pair: RSAKeyPair
    ) -> None:
        """A body naming `subject_value: cust_victim` alongside a genuine
        bearer for `cust_attacker` approves the code for the attacker, never
        the name in the body. Asserted on the stored `customer_ref`, the value
        `/token` reads, since `/token` has minted nothing from it since
        2026-09-30."""
        async with _client(app) as client:
            device = await _start_device_grant(client, client_id="cust_victim")
            await scan_in_store(app, device["user_code"], "cust_attacker")

            approve_resp = await client.post(
                "/approve",
                json={"user_code": device["user_code"], "subject_value": "cust_victim"},
                headers=bearer(key_pair, subject="cust_attacker"),
            )
            assert approve_resp.status_code == 200

            token_resp = await client.post(
                "/token",
                data={"grant_type": "device_code", "device_code": device["device_code"]},
            )

        assert token_resp.status_code == 503
        assert token_resp.json() == ISSUANCE_DISABLED_BODY

        stored = await app.state.device_code_store.get_device_code(device["device_code"])
        assert stored is not None
        assert stored.customer_ref == "cust_attacker"
        assert "cust_victim" not in token_resp.text


# ---------------------------------------------------------------------------
# The user_code pairing code (audit finding C-04).
# ---------------------------------------------------------------------------


class TestUserCodeAcceptedForms:
    """RFC 8628 §6.1: accept a pairing code the way a human types or pastes
    it -- ``services/confirm/device_auth.py::_normalize_user_code``."""

    async def test_display_form_with_dashes(self, app: Starlette, key_pair: RSAKeyPair) -> None:
        async with _client(app) as client:
            device = await _start_device_grant(client)
            resp = await _approve(app, client, device, bearer(key_pair))
        assert resp.status_code == 200

    async def test_bare_form_without_dashes(self, app: Starlette, key_pair: RSAKeyPair) -> None:
        async with _client(app) as client:
            device = await _start_device_grant(client)
            bare = device["user_code"].replace("-", "")
            resp = await _approve(app, client, device, bearer(key_pair), user_code=bare)
        assert resp.status_code == 200

    async def test_lowercase_form(self, app: Starlette, key_pair: RSAKeyPair) -> None:
        async with _client(app) as client:
            device = await _start_device_grant(client)
            resp = await _approve(
                app, client, device, bearer(key_pair), user_code=device["user_code"].lower()
            )
        assert resp.status_code == 200


class TestTokenResponseNeverIncludesAWriteToken:
    """Audit finding C-01: aud=payments.svc scope=payments:execute must
    never reach an HTTP client from this endpoint again. Since 2026-09-30
    the same holds for the read token: the approved body carries no token."""

    async def test_approved_exchange_body_has_exactly_the_two_error_keys(
        self, app: Starlette, key_pair: RSAKeyPair
    ) -> None:
        async with _client(app) as client:
            device = await _start_device_grant(client)
            approve = await _approve(app, client, device, bearer(key_pair))
            assert approve.status_code == 200

            resp = await client.post(
                "/token",
                data={"grant_type": "device_code", "device_code": device["device_code"]},
            )

        assert resp.status_code == 503
        data = resp.json()
        assert set(data) == {"error", "error_description"}
        assert "write_token" not in data
        assert "access_token" not in data


# ---------------------------------------------------------------------------
# approve_callback's own fail-closed branch, called directly.
# ---------------------------------------------------------------------------


class TestApproveCallbackHandlerFailsClosedWithoutMiddleware:
    """`services/confirm/device_auth.py::approve_callback` checks
    `verified_subject(request)` itself and returns 401 on `None`. That
    branch is unreachable through the assembled app -- `AppAssertionMiddleware`
    already refuses first -- which is exactly why it is worth pinning by
    calling the handler directly, bypassing the middleware entirely: a
    future route table that forgets to wire the middleware must still
    refuse, not fall through to a handler that trusts the request body."""

    async def test_handler_called_directly_with_no_seeded_assertion_is_401(self) -> None:
        async def receive() -> dict[str, Any]:
            return {"type": "http.request", "body": b"", "more_body": False}

        request = Request({"type": "http", "state": {}}, receive)
        resp = await approve_callback(request)

        assert resp.status_code == 401
        assert resp.headers["www-authenticate"] == 'Bearer error="invalid_token"'

    async def test_handler_called_directly_with_seeded_assertion_reaches_body_validation(
        self, app: Starlette
    ) -> None:
        """Seeding `scope["state"]` the way `AppAssertionMiddleware` would
        proves the 401 above is specifically about the missing assertion,
        not about anything else a direct call skips."""
        body = json.dumps({"user_code": ""}).encode()

        async def receive() -> dict[str, Any]:
            return {"type": "http.request", "body": body, "more_body": False}

        scope: dict[str, Any] = {
            "type": "http",
            "method": "POST",
            "path": "/approve",
            "headers": [(b"content-type", b"application/json")],
            "app": app,
            "state": {ASSERTION_STATE_KEY: AppAssertion(subject="cust_7f3a", claims={})},
        }
        request = Request(scope, receive)
        resp = await approve_callback(request)

        # Reaches past the 401 branch straight to body validation -- proof
        # the seeded assertion is what let it through. `resp` is Starlette's
        # `JSONResponse`, which has no `.json()` (that is an httpx2/requests
        # method on a *received* response); decode `.body` instead.
        assert resp.status_code == 400
        assert json.loads(bytes(resp.body))["error"] == "invalid_request"


# ---------------------------------------------------------------------------
# The floor under POSTERN_DEVICE_CODE_TTL_SECONDS (bug B1).
# ---------------------------------------------------------------------------


class TestTheDeviceCodeTtlFloor:
    """A TTL an operator can set but the store cannot represent.

    `postern_core.auth.device_codes`'s `RedisDeviceCodeStore` computes its
    TTL with ``int()``, which TRUNCATES, so a code asked for one second has
    roughly 0.9999 left by the time that line runs, floors to zero, and the
    ``if ttl_seconds > 0`` guard skips both the ``SETEX`` and the ``ZADD``.
    Measured on 2026-09-25 against redis:7-alpine::

        expires_in=   1  raw=0.999982  int()=0  stored=NO -- nothing written
        expires_in=   2  raw=1.999990  int()=1  stored=YES
        expires_in= 900  raw=899.999992  int()=899  stored=YES

    ``create_device_code`` returned a `DeviceCode` in all three rows. In the
    first it had written nothing, so the browser polls ``/token`` and is told
    ``invalid_grant`` -- "your code was never real" -- about a code this
    service had just minted for it. `InMemoryDeviceCodeStore` stores that
    same code, so the two backends disagree on the same call.

    WHAT THIS BOUNDS, AND WHAT IT DOES NOT. The floor is on the SETTING,
    ``POSTERN_DEVICE_CODE_TTL_SECONDS``, which is the only path an operator
    can reach that arithmetic from. It is NOT on ``create_device_code``'s
    ``expires_in`` parameter, which any library caller still passes freely
    and which `TestTheFloorIsNotOnCreateDeviceCode` below pins as unchanged.
    """

    def test_the_variable_is_named_in_the_refusal(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The operator has to find the variable to fix it.

        Same posture as `services/confirm/settings.py`'s `_positive_int`: a
        misconfiguration that would quietly change a control's meaning fails
        when the app is assembled, and says which name to go and edit.
        """
        monkeypatch.setenv("POSTERN_DEVICE_CODE_TTL_SECONDS", "5")
        with pytest.raises(ValueError, match="POSTERN_DEVICE_CODE_TTL_SECONDS"):
            ConfirmSettings.from_env()

    @pytest.mark.parametrize("below", ["0", "1", "2", "5", "29", "-1", "-900"])
    def test_a_value_below_the_floor_refuses_at_startup(
        self, monkeypatch: pytest.MonkeyPatch, below: str
    ) -> None:
        """Including ``2``, which the store CAN represent but a human cannot use.

        Falling back to 900 would be worse than having no knob at all: the
        operator would be running a lifetime they never chose, and would find
        out from a customer who cannot pair a device.
        """
        monkeypatch.setenv("POSTERN_DEVICE_CODE_TTL_SECONDS", below)
        with pytest.raises(ValueError, match=str(MIN_DEVICE_CODE_TTL_SECONDS)):
            ConfirmSettings.from_env()

    @pytest.mark.parametrize("bad", ["abc", "1.5", "9 00", "  ", "30s"])
    def test_a_non_integer_refuses_at_startup(
        self, monkeypatch: pytest.MonkeyPatch, bad: str
    ) -> None:
        monkeypatch.setenv("POSTERN_DEVICE_CODE_TTL_SECONDS", bad)
        with pytest.raises(ValueError, match="POSTERN_DEVICE_CODE_TTL_SECONDS"):
            ConfirmSettings.from_env()

    def test_the_floor_itself_is_accepted(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A floor that refused its own value would be an off-by-one, not a bound."""
        monkeypatch.setenv("POSTERN_DEVICE_CODE_TTL_SECONDS", str(MIN_DEVICE_CODE_TTL_SECONDS))
        assert ConfirmSettings.from_env().device_code_ttl_seconds == MIN_DEVICE_CODE_TTL_SECONDS

    @pytest.mark.parametrize("raised", ["31", "300", "900", "1800", "3600"])
    def test_a_value_at_or_above_the_floor_is_read_from_the_environment(
        self, monkeypatch: pytest.MonkeyPatch, raised: str
    ) -> None:
        monkeypatch.setenv("POSTERN_DEVICE_CODE_TTL_SECONDS", raised)
        assert ConfirmSettings.from_env().device_code_ttl_seconds == int(raised)

    def test_an_unset_or_empty_variable_keeps_the_default(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("POSTERN_DEVICE_CODE_TTL_SECONDS", raising=False)
        unset = ConfirmSettings.from_env().device_code_ttl_seconds
        monkeypatch.setenv("POSTERN_DEVICE_CODE_TTL_SECONDS", "")
        assert ConfirmSettings.from_env().device_code_ttl_seconds == unset == 900

    def test_the_default_clears_the_floor(self) -> None:
        """A floor above the default would refuse an unconfigured service."""
        assert ConfirmSettings().device_code_ttl_seconds >= MIN_DEVICE_CODE_TTL_SECONDS
        assert ConfirmSettings.for_testing().device_code_ttl_seconds >= MIN_DEVICE_CODE_TTL_SECONDS


class TestTheFloorIsDerivedAndNotPicked:
    """The three bounds the number sits above, each re-derived here.

    If any of them moves, this fails and the working in
    `services/confirm/settings.py` has to be rewritten rather than quietly
    becoming wrong.
    """

    def test_it_clears_the_truncation_cliff(self) -> None:
        """Below `SHORTEST_STORED_TTL` the Redis backend stores nothing at all.

        tests/test_redis_backed_stores.py::SHORTEST_STORED_TTL carries the
        measurement. This asserts the floor is not merely AT that cliff but
        well clear of it, so no rounding anywhere can reach it.
        """
        assert MIN_DEVICE_CODE_TTL_SECONDS >= SHORTEST_STORED_TTL * 10

    def test_it_clears_the_browsers_first_poll(self) -> None:
        """``token_endpoint`` answers ``slow_down`` before ``interval`` elapses.

        A TTL at or under the poll interval expires before the browser is
        allowed to ask for the first time, so every pairing would fail.
        """
        interval = ConfirmSettings().device_poll_interval_seconds
        assert MIN_DEVICE_CODE_TTL_SECONDS > interval
        assert MIN_DEVICE_CODE_TTL_SECONDS >= interval * 6, "room for several polls"

    def test_it_clears_the_only_measured_leg_of_the_approval(self) -> None:
        """Server-side identity verification: 5 to 15 seconds (CLAUDE.md).

        It is the ONLY leg of scan-then-approve this repository puts a number
        on. The human legs are unmeasured here and the floor deliberately
        claims nothing about them.
        """
        longest_measured_identity_verification = 15
        assert MIN_DEVICE_CODE_TTL_SECONDS >= longest_measured_identity_verification * 2


class TestTheFloorIsNotOnCreateDeviceCode:
    """The other knob, unchanged -- which is the point of bounding the setting.

    A floor on ``expires_in`` would have rewritten
    tests/test_confirm_rate_limit.py's reaper fixtures and
    tests/test_redis_backed_stores.py::SHORTEST_STORED_TTL's codes, and would
    have bounded a parameter no operator can reach. The store's contract is
    unchanged; the environment variable is what narrowed.
    """

    async def test_the_in_memory_store_still_takes_a_one_second_lifetime(self) -> None:
        store = InMemoryDeviceCodeStore()
        code = await store.create_device_code(
            client_id="c", scopes="s", verification_uri="https://x.invalid/v", expires_in=1
        )
        assert await store.get_device_code(code.device_code) is code
        assert (code.expires_at - datetime.now(UTC)).total_seconds() <= 1

    def test_the_signature_defaults_are_untouched(self) -> None:
        """900 on the in-memory store, ``None`` on Redis (its own default TTL)."""
        assert (
            inspect.signature(InMemoryDeviceCodeStore.create_device_code)
            .parameters["expires_in"]
            .default
            == 900
        )
        assert (
            inspect.signature(RedisDeviceCodeStore.create_device_code)
            .parameters["expires_in"]
            .default
            is None
        )


class TestAPairingCompletesAtTheConfiguredTtl:
    """End to end, through the real composition root, at two lifetimes.

    A floor is only worth having if the values above it still work, so this
    drives the whole grant -- authorize, poll, approve, poll -- rather than
    reading the setting back off the dataclass.
    """

    @pytest.mark.parametrize("ttl", [900, 1800])
    async def test_a_pairing_completes(self, key_pair: RSAKeyPair, ttl: int) -> None:
        verifier = JWTVerifier(public_key=key_pair.public_key, issuer=ISSUER, audience=AUDIENCE)
        app = create_confirm_app(
            dataclasses.replace(ConfirmSettings.for_testing(), device_code_ttl_seconds=ttl),
            assertion_verifier=verifier,
            device_key_store=no_enrolled_devices(),
        )
        async with _client(app) as client:
            device = await _start_device_grant(client, client_id="browser-ttl")
            assert device["expires_in"] == ttl

            pending = await client.post(
                "/token", data={"grant_type": "device_code", "device_code": device["device_code"]}
            )
            assert pending.json()["error"] == "authorization_pending"

            approved = await _approve(
                app, client, device, bearer(key_pair, subject="cust_abc"), scanned_by="cust_abc"
            )
            assert approved.status_code == 200

            # The pairing completes as far as issuance, which is disabled.
            issued = await client.post(
                "/token", data={"grant_type": "device_code", "device_code": device["device_code"]}
            )
            assert issued.status_code == 503
            assert issued.json() == ISSUANCE_DISABLED_BODY

            stored = await app.state.device_code_store.get_device_code(device["device_code"])
            assert stored is not None, "the code the pairing used was really stored"
            assert not stored.is_expired


# ---------------------------------------------------------------------------
# Spent device codes, and exchanges that spend nothing.
# ---------------------------------------------------------------------------


async def _exchange(client: httpx2.AsyncClient, device_code: str) -> httpx2.Response:
    """``POST /token`` with the device code grant, as the browser sends it."""
    return await client.post(
        "/token",
        data={"grant_type": "device_code", "device_code": device_code},
    )


class TestASpentDeviceCodeStaysSpent:
    """A code that was spent is refused, and a refused exchange spends nothing.

    UNTIL 2026-09-30 THE EXCHANGE THAT MINTED SPENT THE CODE, and
    ``dev-docs/decisions/0012-device-code-single-use.md`` carries why one
    approved code is worth at most one token: RFC 8628 §5.2 calls what a
    device code redeems an authorization code, and RFC 6749 §10.5 makes those
    "short lived and single-use". Issuance is now disabled pending the layer-1
    session token, so no exchange spends a code, and these tests reach a spent
    code the way a deployment still can: through the store, as a build before
    2026-09-30 left it, in a shared Redis that outlives the deploy.

    The spent-code refusal is therefore the one tested here, together with the
    new property it sits beside: a refused exchange of an approved code leaves
    it unspent, including when two of them race.
    """

    async def test_a_refused_exchange_leaves_the_code_unspent(
        self, app: Starlette, key_pair: RSAKeyPair
    ) -> None:
        """Two polls of one approved code a full interval apart, one answer,
        and nothing spent. The wait is simulated by moving the recorded poll
        back one interval; a poll inside it is ``slow_down`` (pinned in
        ``tests/test_pairing_audit.py``)."""
        async with _client(app) as client:
            device = await _start_device_grant(client)
            assert (await _approve(app, client, device, bearer(key_pair))).status_code == 200

            first = await _exchange(client, device["device_code"])
            app.state._approved_poll_times[device["device_code"]] -= timedelta(
                seconds=app.state.settings.device_poll_interval_seconds
            )
            second = await _exchange(client, device["device_code"])

        assert first.status_code == second.status_code == 503
        assert first.json() == second.json() == ISSUANCE_DISABLED_BODY
        stored = await app.state.device_code_store.get_device_code(device["device_code"])
        assert stored is not None
        assert stored.exchanged_at is None

    async def test_a_spent_code_stays_in_the_store_and_is_refused(
        self, app: Starlette, key_pair: RSAKeyPair
    ) -> None:
        """MARKED, never revoked, and the audit story is what decides it.

        Revoking would delete the row, and a replay would then be answered by
        the unknown-code branch, which resolves no identity and so writes no
        ``audit_log`` row -- losing the one event on this endpoint most worth
        recording.
        """
        store: InMemoryDeviceCodeStore = app.state.device_code_store
        async with _client(app) as client:
            device = await _start_device_grant(client)
            assert (await _approve(app, client, device, bearer(key_pair))).status_code == 200
            assert await store.consume_device_code(device["device_code"]) is True

            replay = await _exchange(client, device["device_code"])

        assert replay.status_code == 400
        assert replay.json()["error"] == "invalid_grant"
        spent = await store.get_device_code(device["device_code"])
        assert spent is not None, "the row a replay must be recorded against was deleted"
        assert spent.exchanged_at is not None
        assert spent.approved is True

    async def test_the_refusal_is_the_one_an_unknown_code_gets(
        self, app: Starlette, key_pair: RSAKeyPair
    ) -> None:
        """The response is not an oracle, and the table is where the two differ.

        A party holding a guessed device code must not learn from a status or
        a body that the value existed, was approved and was spent. That
        distinction is worth recording and worth withholding, so it goes in
        ``audit_log.detail`` where only the operator reads it.
        """
        store: InMemoryDeviceCodeStore = app.state.device_code_store
        async with _client(app) as client:
            device = await _start_device_grant(client)
            assert (await _approve(app, client, device, bearer(key_pair))).status_code == 200
            assert await store.consume_device_code(device["device_code"]) is True

            spent = await _exchange(client, device["device_code"])
            never_existed = await _exchange(client, "no-such-device-code")

        assert spent.status_code == never_existed.status_code == 400
        assert spent.json() == never_existed.json()

    async def test_a_replay_is_refused_without_consulting_the_revocation_store(
        self, app: Starlette, key_pair: RSAKeyPair
    ) -> None:
        """A spent code is refused on the row, before ZT-7 is asked anything.

        Otherwise a replay arriving during a revocation-store outage would be
        answered 503 ``temporarily_unavailable``, a code that promises
        retryability for a grant no retry can ever redeem.
        """
        store: InMemoryDeviceCodeStore = app.state.device_code_store
        async with _client(app) as client:
            device = await _start_device_grant(client)
            assert (await _approve(app, client, device, bearer(key_pair))).status_code == 200
            assert await store.consume_device_code(device["device_code"]) is True

            class Unavailable:
                async def is_customer_revoked(self, customer_ref: str) -> bool:
                    raise RevocationStoreUnavailable("the revocation store is gone")

            app.state.postern_revocation_store = Unavailable()
            replay = await _exchange(client, device["device_code"])

        assert replay.status_code == 400
        assert replay.json()["error"] == "invalid_grant"

    async def test_two_concurrent_exchanges_issue_nothing_and_spend_nothing(
        self, app: Starlette, key_pair: RSAKeyPair
    ) -> None:
        """The race this class used to force for the claim, kept for the refusal.

        Until the pacing of approved codes it held two requests inside the
        revocation check with a barrier, so both reached the point where a
        token used to be minted. Now the pacing check lets exactly one through
        (the check and the record have no ``await`` between them), so the
        other is answered ``slow_down`` before the revocation check, and a
        barrier of two would never release. Neither gets a token, and the
        code is still unspent afterwards.
        """
        async with _client(app) as client:
            device = await _start_device_grant(client)
            assert (await _approve(app, client, device, bearer(key_pair))).status_code == 200

            both = await asyncio.gather(
                _exchange(client, device["device_code"]),
                _exchange(client, device["device_code"]),
            )

        assert sorted(r.status_code for r in both) == [400, 503]
        by_status = {r.status_code: r for r in both}
        assert by_status[503].json() == ISSUANCE_DISABLED_BODY
        assert by_status[400].json()["error"] == "slow_down"
        assert [jwt_shaped_strings(r.text) for r in both] == [[], []]
        stored = await app.state.device_code_store.get_device_code(device["device_code"])
        assert stored is not None
        assert stored.exchanged_at is None


class TestConsumingADeviceCodeInTheStore:
    """``consume_device_code``, the atomic claim the mint sits behind.

    A separate contract from ``approve_scanned``'s and the same shape:
    ``True`` to the caller that moved the code, ``False`` to every other,
    including one that arrives at the same instant.
    """

    async def test_the_first_call_wins_and_a_second_is_refused(
        self, store: InMemoryDeviceCodeStore
    ) -> None:
        code = await store.create_device_code(
            client_id="browser-1",
            scopes="accounts:read",
            verification_uri="https://auth.example.com/verify",
        )

        assert await store.consume_device_code(code.device_code) is True
        assert await store.consume_device_code(code.device_code) is False

    async def test_it_marks_the_code_rather_than_removing_it(
        self, store: InMemoryDeviceCodeStore
    ) -> None:
        code = await store.create_device_code(
            client_id="browser-1",
            scopes="accounts:read",
            verification_uri="https://auth.example.com/verify",
        )

        await store.consume_device_code(code.device_code)

        stored = await store.get_device_code(code.device_code)
        assert stored is not None
        assert stored.exchanged_at is not None
        assert stored.device_code == code.device_code

    async def test_a_code_the_store_never_held_cannot_be_consumed(
        self, store: InMemoryDeviceCodeStore
    ) -> None:
        assert await store.consume_device_code("never-existed") is False

    async def test_two_concurrent_claims_answer_true_to_exactly_one(
        self, store: InMemoryDeviceCodeStore
    ) -> None:
        """The contract the endpoint's one-token property rests on.

        A claim that read, awaited anything, and then wrote would answer
        ``True`` to both of these.
        """
        code = await store.create_device_code(
            client_id="browser-1",
            scopes="accounts:read",
            verification_uri="https://auth.example.com/verify",
        )

        won = await asyncio.gather(
            store.consume_device_code(code.device_code),
            store.consume_device_code(code.device_code),
        )

        assert sorted(won) == [False, True]

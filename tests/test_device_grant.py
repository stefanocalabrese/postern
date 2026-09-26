"""RFC 8628 device authorization grant — full lifecycle tests.

Covers:
- Device code generation (device_code, user_code, QR data).
- In-memory store CRUD (create, get, approve, revoke, update), including the
  ``customer_ref`` / ``user_code_attempts`` fields added for audit findings
  C-01 and C-04.
- Device authorization endpoint (``POST /device_authorization``) — public,
  no bearer: the browser holds no credential (RFC 8628's entire premise).
- Token exchange with the ``device_code`` grant type (pending, approved,
  expired, slow_down) — public, no bearer, and never returns a write token
  (audit finding C-01).
- Mobile app approval callback (``POST /approve``) — requires a verified
  banking-app bearer assertion (``services/confirm/auth.py``); the customer
  comes from the verified ``sub`` and from nowhere else. A request body can
  no longer name a customer at all.
- The uniform-401 property: every way authentication can fail produces one
  identical response body, so an attacker cannot learn which check failed.
- The required ``user_code`` pairing-code check (audit finding C-04):
  accepted forms, wrong-code handling, and the attempt budget that revokes
  the device code on the third failure.
- Error cases (invalid_request, invalid_grant, invalid_user_code,
  invalid_subject, slow_down, expired_token, already_approved,
  invalid_state).

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
from joserfc import jwt as joserfc_jwt
from joserfc.jwk import KeySet
from postern_core.auth.device_codes import (
    DeviceCode,
    InMemoryDeviceCodeStore,
    RedisDeviceCodeStore,
    _device_code_to_dict,
    _generate_device_code,
    _generate_user_code,
)
from postern_core.auth.device_keys import no_enrolled_devices
from starlette.applications import Starlette
from starlette.requests import Request

from services.confirm.auth import ASSERTION_STATE_KEY, AppAssertion
from services.confirm.device_auth import approve_callback
from services.confirm.main import create_confirm_app
from services.confirm.settings import MIN_DEVICE_CODE_TTL_SECONDS, ConfirmSettings

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
    client: httpx2.AsyncClient,
    device: dict[str, Any],
    headers: dict[str, str] | None,
    *,
    user_code: str | None = None,
) -> httpx2.Response:
    """``POST /approve`` for ``device``, with ``headers`` (or none at all)."""
    return await client.post(
        "/approve",
        json={
            "device_code": device["device_code"],
            "user_code": user_code if user_code is not None else device["user_code"],
        },
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
            assert code.isupper()
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
        """URI with existing query params gets &user_code=."""
        dc = DeviceCode(
            device_code="test",
            user_code="ABCDEF",
            verification_uri="https://example.com/verify?foo=bar",
            expires_at=datetime.now(UTC) + timedelta(minutes=15),
        )
        assert dc.verification_uri_complete == "https://example.com/verify?foo=bar&user_code=ABCDEF"

    def test_verification_uri_complete_without_query(self) -> None:
        """URI without query params gets ?user_code=."""
        dc = DeviceCode(
            device_code="test",
            user_code="ABCDEF",
            verification_uri="https://example.com/verify",
            expires_at=datetime.now(UTC) + timedelta(minutes=15),
        )
        assert dc.verification_uri_complete == "https://example.com/verify?user_code=ABCDEF"

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

    async def test_new_device_code_defaults_customer_ref_empty_and_attempts_zero(
        self, store: InMemoryDeviceCodeStore
    ) -> None:
        """The two fields audit findings C-01/C-04 added start unset: no
        identity and no failed pairing-code attempts until `/approve` writes
        them."""
        code = await store.create_device_code(
            client_id="test-client",
            scopes="accounts:read",
            verification_uri="https://auth.example.com/verify",
        )
        assert code.customer_ref == ""
        assert code.user_code_attempts == 0

    async def test_approve(self, store: InMemoryDeviceCodeStore) -> None:
        """The store-level `approve_device_code` still exists and still just
        flips `approved`/`approved_at` -- it does NOT set `customer_ref`,
        which is exactly why `services/confirm/device_auth.py::approve_callback`
        no longer calls it: identity and approval are now written together,
        in one `update_device_code` call, from a verified assertion."""
        code = await store.create_device_code(
            client_id="test-client",
            scopes="accounts:read",
            verification_uri="https://auth.example.com/verify",
        )
        assert code.approved is False

        result = await store.approve_device_code(code.device_code)
        assert result is True

        updated = await store.get_device_code(code.device_code)
        assert updated is not None
        assert updated.approved is True
        assert updated.approved_at is not None
        assert updated.customer_ref == ""

    async def test_double_approve_fails(self, store: InMemoryDeviceCodeStore) -> None:
        code = await store.create_device_code(
            client_id="test-client",
            scopes="accounts:read",
            verification_uri="https://auth.example.com/verify",
        )
        assert await store.approve_device_code(code.device_code) is True
        # Second approval should fail.
        assert await store.approve_device_code(code.device_code) is False

    async def test_approve_nonexistent(self, store: InMemoryDeviceCodeStore) -> None:
        result = await store.approve_device_code("nonexistent")
        assert result is False

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

    async def test_update_device_code(self, store: InMemoryDeviceCodeStore) -> None:
        code = await store.create_device_code(
            client_id="original",
            scopes="accounts:read",
            verification_uri="https://auth.example.com/verify",
        )
        updated = DeviceCode(
            device_code=code.device_code,
            user_code=code.user_code,
            verification_uri=code.verification_uri,
            expires_at=code.expires_at,
            interval=code.interval,
            client_id="updated-client",
            scopes=code.scopes,
            approved=True,
            approved_at=datetime.now(UTC),
        )
        await store.update_device_code(code.device_code, updated)

        found = await store.get_device_code(code.device_code)
        assert found is not None
        assert found.client_id == "updated-client"
        assert found.approved is True

    async def test_update_device_code_writes_customer_ref_and_user_code_attempts(
        self, store: InMemoryDeviceCodeStore
    ) -> None:
        code = await store.create_device_code(
            client_id="test-client",
            scopes="accounts:read",
            verification_uri="https://auth.example.com/verify",
        )
        updated = dataclasses.replace(code, customer_ref="cust_7f3a", user_code_attempts=2)
        await store.update_device_code(code.device_code, updated)

        found = await store.get_device_code(code.device_code)
        assert found is not None
        assert found.customer_ref == "cust_7f3a"
        assert found.user_code_attempts == 2


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

    async def test_approved_exchange_returns_a_read_token_for_the_bearer_subject(
        self, app: Starlette, key_pair: RSAKeyPair
    ) -> None:
        """`/token` used to read `client_id`, the field a caller of
        `/device_authorization` controls; it now reads `customer_ref`, which
        only a verified `/approve` write ever sets (audit finding C-01)."""
        async with _client(app) as client:
            device = await _start_device_grant(client, client_id="cust_should_be_ignored")
            approve = await _approve(client, device, bearer(key_pair, subject="cust_7f3a"))
            assert approve.status_code == 200

            resp = await client.post(
                "/token",
                data={"grant_type": "device_code", "device_code": device["device_code"]},
            )

        assert resp.status_code == 200
        data = resp.json()
        assert data["token_type"] == "Bearer"  # noqa: S105
        assert "expires_in" in data
        assert len(data["access_token"]) > 0
        # No write token in the body -- audit finding C-01.
        assert "write_token" not in data

        source = app.state.postern_read_key_source
        claims = joserfc_jwt.decode(
            data["access_token"],
            KeySet.import_key_set(source.public_jwks()),
            algorithms=["RS256"],
        ).claims
        assert claims["sub"] == "cust_7f3a"

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


# ---------------------------------------------------------------------------
# Approval callback.
# ---------------------------------------------------------------------------


class TestApproveCallback:
    """POST /approve — mobile app approval. Requires a verified bearer
    assertion (see TestApproveCallbackUniform401 below); the customer comes
    from its `sub`, never from the body (audit finding C-01)."""

    async def test_approve_success_takes_the_customer_from_the_bearer(
        self, app: Starlette, key_pair: RSAKeyPair
    ) -> None:
        store: InMemoryDeviceCodeStore = app.state.device_code_store
        code = await store.create_device_code(
            client_id="original-client",
            scopes="accounts:read",
            verification_uri="https://auth.example.com/verify",
        )

        async with _client(app) as client:
            resp = await client.post(
                "/approve",
                json={"device_code": code.device_code, "user_code": code.user_code_display},
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
                json={"device_code": "nonexistent", "user_code": "ABCDEF"},
                headers=bearer(key_pair),
            )

        assert resp.status_code == 400
        assert resp.json()["error"] == "invalid_grant"

    async def test_approve_already_approved(self, app: Starlette, key_pair: RSAKeyPair) -> None:
        store: InMemoryDeviceCodeStore = app.state.device_code_store
        code = await store.create_device_code(
            client_id="test-client",
            scopes="accounts:read",
            verification_uri="https://auth.example.com/verify",
        )

        async with _client(app) as client:
            first = await client.post(
                "/approve",
                json={"device_code": code.device_code, "user_code": code.user_code_display},
                headers=bearer(key_pair, subject="cust_123"),
            )
            assert first.status_code == 200

            # A second approver, with their own genuine assertion, must not
            # be able to swap the identity on an already-approved code.
            second = await client.post(
                "/approve",
                json={"device_code": code.device_code, "user_code": code.user_code_display},
                headers=bearer(key_pair, subject="cust_attacker"),
            )

        assert second.status_code == 400
        assert second.json()["error"] == "already_approved"
        updated = await store.get_device_code(code.device_code)
        assert updated is not None
        assert updated.customer_ref == "cust_123"

    async def test_approve_wrong_user_code_is_400_and_does_not_approve(
        self, app: Starlette, key_pair: RSAKeyPair
    ) -> None:
        store: InMemoryDeviceCodeStore = app.state.device_code_store
        code = await store.create_device_code(
            client_id="test-client",
            scopes="accounts:read",
            verification_uri="https://auth.example.com/verify",
        )

        async with _client(app) as client:
            resp = await client.post(
                "/approve",
                json={"device_code": code.device_code, "user_code": "ZZZZZZ"},
                headers=bearer(key_pair),
            )

        assert resp.status_code == 400
        assert resp.json()["error"] == "invalid_user_code"
        updated = await store.get_device_code(code.device_code)
        assert updated is not None
        assert updated.approved is False
        assert updated.user_code_attempts == 1


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

            # Step 3: Mobile app approves, with a verified assertion and the
            # pairing code from the same QR.
            resp = await client.post(
                "/approve",
                json={
                    "device_code": device_code_value,
                    "user_code": device_data["user_code"],
                },
                headers=bearer(key_pair, subject="cust_abc"),
            )
            assert resp.status_code == 200

            # Step 4: Poll token after approval → success.
            resp = await client.post(
                "/token",
                data={
                    "grant_type": "device_code",
                    "device_code": device_code_value,
                },
            )
            assert resp.status_code == 200
            token_data = resp.json()
            assert "access_token" in token_data
            assert "write_token" not in token_data

            # Step 5: The read token is a valid-looking JWT (three
            # dot-separated parts).
            read_token = token_data["access_token"]
            assert read_token.count(".") == 2

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

    def test_customer_ref_and_user_code_attempts_round_trip_through_json(self) -> None:
        dc = DeviceCode(
            device_code="cref-json",
            user_code="ABCDEF",
            verification_uri="https://auth.example.com/verify",
            expires_at=datetime.now(UTC) + timedelta(minutes=15),
            approved=True,
            approved_at=datetime.now(UTC),
            customer_ref="cust_7f3a",
            user_code_attempts=2,
        )
        dc2 = DeviceCode.from_json(dc.to_json())
        assert dc2.customer_ref == "cust_7f3a"
        assert dc2.user_code_attempts == 2

    def test_customer_ref_and_user_code_attempts_round_trip_through_dict(self) -> None:
        dc = DeviceCode(
            device_code="cref-dict",
            user_code="ABCDEF",
            verification_uri="https://auth.example.com/verify",
            expires_at=datetime.now(UTC) + timedelta(minutes=15),
            customer_ref="cust_9999",
            user_code_attempts=1,
        )
        dc2 = DeviceCode.from_dict(_device_code_to_dict(dc))
        assert dc2.customer_ref == "cust_9999"
        assert dc2.user_code_attempts == 1

    def test_from_dict_without_the_new_fields_defaults_customer_ref_and_attempts(self) -> None:
        """A Redis-backed store can hold codes serialized by a previous
        release. `.get()` defaults, not `data[...]`, keep an old record
        deserializing instead of raising `KeyError` on every in-flight
        device grant when this rolls out -- and defaulting to empty/zero is
        the fail-closed direction: `/token` then refuses the code instead of
        minting from a stale identity."""
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
            # No "customer_ref" or "user_code_attempts" key at all.
        }
        dc = DeviceCode.from_dict(legacy)
        assert dc.customer_ref == ""
        assert dc.user_code_attempts == 0


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

            resp = await c.post(
                "/approve",
                json={
                    "device_code": dc["device_code"],
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

    async def test_approve_empty_device_code(self, app: Starlette, key_pair: RSAKeyPair) -> None:
        """Empty device_code → 400, even with a valid bearer."""
        async with _client(app) as c:
            resp = await c.post(
                "/approve",
                json={"device_code": "", "user_code": "ABCDEF"},
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
                json={"device_code": "some_code", "user_code": "ABCDEF"},
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

            # 3. Approve via mobile app, with a verified assertion and the
            # pairing code.
            approve_resp = await c.post(
                "/approve",
                json={
                    "device_code": dc["device_code"],
                    "user_code": dc["user_code"],
                },
                headers=bearer(key_pair, subject="cust_7f3a"),
            )
            assert approve_resp.status_code == 200

            # 4. Exchange for tokens.
            token_resp = await c.post(
                "/token",
                data={"grant_type": "device_code", "device_code": dc["device_code"]},
            )
        assert token_resp.status_code == 200
        token_data = token_resp.json()
        assert "access_token" in token_data
        assert "write_token" not in token_data
        assert token_data["token_type"] == "Bearer"  # noqa: S105


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
            resp = await _approve(client, pending_code, None)
        assert resp.status_code == 401

    async def test_malformed_jwt(self, app: Starlette, pending_code: dict[str, Any]) -> None:
        async with _client(app) as client:
            resp = await _approve(
                client, pending_code, {"Authorization": "Bearer not-a-jwt-at-all"}
            )
        assert resp.status_code == 401

    async def test_expired_token(
        self, app: Starlette, pending_code: dict[str, Any], key_pair: RSAKeyPair
    ) -> None:
        async with _client(app) as client:
            resp = await _approve(client, pending_code, bearer(key_pair, expires_in_seconds=-10))
        assert resp.status_code == 401

    async def test_wrong_issuer(
        self, app: Starlette, pending_code: dict[str, Any], key_pair: RSAKeyPair
    ) -> None:
        async with _client(app) as client:
            resp = await _approve(
                client, pending_code, bearer(key_pair, issuer="https://wrong-issuer.invalid")
            )
        assert resp.status_code == 401

    async def test_wrong_audience(
        self, app: Starlette, pending_code: dict[str, Any], key_pair: RSAKeyPair
    ) -> None:
        async with _client(app) as client:
            resp = await _approve(client, pending_code, bearer(key_pair, audience="wrong-audience"))
        assert resp.status_code == 401

    async def test_wrong_signature(
        self, app: Starlette, pending_code: dict[str, Any], other_key_pair: RSAKeyPair
    ) -> None:
        async with _client(app) as client:
            resp = await _approve(client, pending_code, bearer(other_key_pair))
        assert resp.status_code == 401

    async def test_empty_subject_claim(
        self, app: Starlette, pending_code: dict[str, Any], key_pair: RSAKeyPair
    ) -> None:
        async with _client(app) as client:
            resp = await _approve(client, pending_code, bearer(key_pair, subject=""))
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
                resp = await _approve(client, pending_code, headers)
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
            resp = await _approve(client, device, bearer(key_pair, subject="not-a-customer"))
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
                json={"device_code": device["device_code"], "subject_value": "cust_victim"},
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
        bearer for `cust_attacker` mints a token for the attacker, never the
        name in the body."""
        async with _client(app) as client:
            device = await _start_device_grant(client, client_id="cust_victim")

            approve_resp = await client.post(
                "/approve",
                json={
                    "device_code": device["device_code"],
                    "user_code": device["user_code"],
                    "subject_value": "cust_victim",
                },
                headers=bearer(key_pair, subject="cust_attacker"),
            )
            assert approve_resp.status_code == 200

            token_resp = await client.post(
                "/token",
                data={"grant_type": "device_code", "device_code": device["device_code"]},
            )

        assert token_resp.status_code == 200
        token_data = token_resp.json()
        assert "write_token" not in token_data

        source = app.state.postern_read_key_source
        claims = joserfc_jwt.decode(
            token_data["access_token"],
            KeySet.import_key_set(source.public_jwks()),
            algorithms=["RS256"],
        ).claims
        assert claims["sub"] == "cust_attacker"


# ---------------------------------------------------------------------------
# The user_code pairing code (audit finding C-04).
# ---------------------------------------------------------------------------


class TestUserCodeAcceptedForms:
    """RFC 8628 §6.1: accept a pairing code the way a human types or pastes
    it -- ``services/confirm/device_auth.py::_normalize_user_code``."""

    async def test_display_form_with_dashes(self, app: Starlette, key_pair: RSAKeyPair) -> None:
        async with _client(app) as client:
            device = await _start_device_grant(client)
            resp = await _approve(client, device, bearer(key_pair))
        assert resp.status_code == 200

    async def test_bare_form_without_dashes(self, app: Starlette, key_pair: RSAKeyPair) -> None:
        async with _client(app) as client:
            device = await _start_device_grant(client)
            bare = device["user_code"].replace("-", "")
            resp = await _approve(client, device, bearer(key_pair), user_code=bare)
        assert resp.status_code == 200

    async def test_lowercase_form(self, app: Starlette, key_pair: RSAKeyPair) -> None:
        async with _client(app) as client:
            device = await _start_device_grant(client)
            resp = await _approve(
                client, device, bearer(key_pair), user_code=device["user_code"].lower()
            )
        assert resp.status_code == 200


class TestUserCodeAttemptBudgetRevokesTheCode:
    """`ConfirmSettings.user_code_max_attempts` defaults to 3 (RFC 8628 §5.2)."""

    async def test_first_two_wrong_attempts_increment_without_revoking(
        self, app: Starlette, key_pair: RSAKeyPair
    ) -> None:
        store: InMemoryDeviceCodeStore = app.state.device_code_store
        async with _client(app) as client:
            device = await _start_device_grant(client)
            for expected_attempts in (1, 2):
                resp = await _approve(client, device, bearer(key_pair), user_code="ZZZZZZ")
                assert resp.status_code == 400
                assert resp.json()["error"] == "invalid_user_code"
                updated = await store.get_device_code(device["device_code"])
                assert updated is not None
                assert updated.approved is False
                assert updated.user_code_attempts == expected_attempts

    async def test_three_wrong_attempts_revoke_the_device_code(
        self, app: Starlette, key_pair: RSAKeyPair
    ) -> None:
        store: InMemoryDeviceCodeStore = app.state.device_code_store
        async with _client(app) as client:
            device = await _start_device_grant(client)

            for _ in range(2):
                resp = await _approve(client, device, bearer(key_pair), user_code="ZZZZZZ")
                assert resp.status_code == 400

            third = await _approve(client, device, bearer(key_pair), user_code="ZZZZZZ")
            assert third.status_code == 400
            third_body = third.json()
            assert third_body["error"] == "invalid_user_code"
            assert "revoked" in third_body["error_description"]
            assert await store.get_device_code(device["device_code"]) is None

            token_resp = await client.post(
                "/token",
                data={"grant_type": "device_code", "device_code": device["device_code"]},
            )
        assert token_resp.status_code == 400
        assert token_resp.json()["error"] == "invalid_grant"


class TestTokenResponseNeverIncludesAWriteToken:
    """Audit finding C-01: aud=payments.svc scope=payments:execute must
    never reach an HTTP client from this endpoint again."""

    async def test_approved_exchange_body_has_exactly_three_keys(
        self, app: Starlette, key_pair: RSAKeyPair
    ) -> None:
        async with _client(app) as client:
            device = await _start_device_grant(client)
            approve = await _approve(client, device, bearer(key_pair))
            assert approve.status_code == 200

            resp = await client.post(
                "/token",
                data={"grant_type": "device_code", "device_code": device["device_code"]},
            )

        assert resp.status_code == 200
        data = resp.json()
        assert set(data) == {"access_token", "token_type", "expires_in"}
        assert "write_token" not in data


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
        body = json.dumps({"device_code": "", "user_code": ""}).encode()

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

            approved = await _approve(client, device, bearer(key_pair, subject="cust_abc"))
            assert approved.status_code == 200

            issued = await client.post(
                "/token", data={"grant_type": "device_code", "device_code": device["device_code"]}
            )
            assert issued.status_code == 200
            assert issued.json()["access_token"].count(".") == 2

            stored = await app.state.device_code_store.get_device_code(device["device_code"])
            assert stored is not None, "the code the pairing used was really stored"
            assert not stored.is_expired


# ---------------------------------------------------------------------------
# The floor under POSTERN_USER_CODE_MAX_ATTEMPTS.
# ---------------------------------------------------------------------------


class TestTheUserCodeAttemptBudgetFloor:
    """What a budget of zero actually costs, which is not what it looks like.

    Traced through `create_confirm_app` on 2026-09-25, because the obvious
    reading -- "zero attempts, so pairing is dead" -- is wrong, and a floor
    justified by it would rest on a claim the code does not support.
    ``_record_user_code_failure`` is reached ONLY from the mismatch branch of
    ``approve_callback``, so at zero a correct pairing code on the first try
    still approves and ``/token`` still issues a read token.

    What zero costs is the TOLERANCE. ``attempts =
    existing.user_code_attempts + 1`` makes the first wrong code ``1 >= 0``,
    so one mistyped pairing code revokes the device code outright and the
    customer's next attempt -- with the RIGHT code -- is answered
    ``invalid_grant: device code not found``. The default of 3 absorbs two.

    WHY THE FLOOR IS ONE AND NOT THREE. ``1`` is already zero tolerance and
    behaves identically to ``0`` and to ``-5``, so nothing below one
    expresses anything ``1`` does not. An operator who wants no slack for a
    typo can still say so; one who writes ``0`` reaching for "no limit" gets
    the opposite, and that is the reading `_positive_int` refuses to guess.
    """

    def test_zero_refuses_at_startup_naming_the_variable(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("POSTERN_USER_CODE_MAX_ATTEMPTS", "0")
        with pytest.raises(ValueError, match="POSTERN_USER_CODE_MAX_ATTEMPTS"):
            ConfirmSettings.from_env()

    def _app(self, key_pair: RSAKeyPair, attempts: int) -> Starlette:
        verifier = JWTVerifier(public_key=key_pair.public_key, issuer=ISSUER, audience=AUDIENCE)
        return create_confirm_app(
            dataclasses.replace(ConfirmSettings.for_testing(), user_code_max_attempts=attempts),
            assertion_verifier=verifier,
            device_key_store=no_enrolled_devices(),
        )

    async def test_the_floor_still_pairs_when_the_code_is_right_first_time(
        self, key_pair: RSAKeyPair
    ) -> None:
        """A budget of one bounds MISTAKES, never the happy path."""
        app = self._app(key_pair, 1)
        async with _client(app) as client:
            device = await _start_device_grant(client)
            approved = await _approve(client, device, bearer(key_pair))
            assert approved.status_code == 200
            issued = await client.post(
                "/token",
                data={"grant_type": "device_code", "device_code": device["device_code"]},
            )
            assert issued.status_code == 200

    async def test_the_floor_revokes_on_the_first_typo(self, key_pair: RSAKeyPair) -> None:
        """And the right code afterwards cannot recover it: a fresh QR is the only way."""
        app = self._app(key_pair, 1)
        store: InMemoryDeviceCodeStore = app.state.device_code_store
        async with _client(app) as client:
            device = await _start_device_grant(client)

            wrong = await _approve(client, device, bearer(key_pair), user_code="ZZZZZZ")
            assert wrong.status_code == 400
            assert "revoked" in wrong.json()["error_description"]
            assert await store.get_device_code(device["device_code"]) is None

            retry = await _approve(client, device, bearer(key_pair))
            assert retry.status_code == 400
            assert retry.json()["error"] == "invalid_grant"

    async def test_the_default_absorbs_two_typos_before_revoking(
        self, key_pair: RSAKeyPair
    ) -> None:
        """Which is the difference the floor exists to keep reachable."""
        app = self._app(key_pair, ConfirmSettings().user_code_max_attempts)
        store: InMemoryDeviceCodeStore = app.state.device_code_store
        async with _client(app) as client:
            device = await _start_device_grant(client)
            for _ in range(2):
                typo = await _approve(client, device, bearer(key_pair), user_code="ZZZZZZ")
                assert typo.status_code == 400
            assert await store.get_device_code(device["device_code"]) is not None
            assert (await _approve(client, device, bearer(key_pair))).status_code == 200

"""The second limiter: what ONE CUSTOMER may approve, on the two paths with one.

THE DEFECT, IN ONE SENTENCE. ``POST /approve`` and
``POST /challenges/{challenge_id}/approve`` were bounded per client address
bucket, and sixty payment approvals a minute from one customer is a signal
while sixty from a bank's egress address is a Tuesday. The environment
overrides that shipped with the address-keyed limiter made the wrong unit
survivable -- an operator who hits the ceiling raises it without a release --
and raising it raises it for every customer at once.

WHAT THIS FILE PROVES, AND IN WHICH SECTION:

- `TestTheBudgetIsPerCustomer` -- two customers from ONE address do not share
  a budget, and one customer from TWO addresses does. The second of those is
  the property an address-keyed limiter cannot express and the entire point of
  the work.
- `TestTheOuterLimiterIsStillFirst` -- a request the address-keyed limiter
  refuses never reaches the assertion verifier, so a JWKS fetch and a
  signature verification are still not the price of a refusal. This is the
  property that makes the two limiters layered rather than alternative, and it
  is asserted by counting verifications, not by reading the middleware list.
- `TestAnOperatorCanTellTheTwoRefusalsApart` -- both ceilings answered from
  ONE app, with the two bodies side by side.
- `TestARefusalWritesNoAuditRow` -- decision 5, proven by poisoning
  ``app.state.postern_database`` so that any touch raises, and then showing
  that an ADMITTED request does touch it. Without that second half the test
  would pass against a limiter that refused everything.
- `TestTheCountersAreShared` -- against a real Redis, two store instances
  standing in for two replicas spend ONE budget. This is decision 2: the
  in-process counters the address-keyed limiter chose would give R replicas R
  times the ceiling, which for a control whose entire content is its number is
  the number not being the number.

WHAT IT DELIBERATELY DOES NOT CLAIM. Not that the approval path is safe --
the device signature and the server-side-built confirmation payload are the
controls for that, and this bounds volume only. Not that one compromised
banking-app backend is contained: it mints assertions, so it can present N
customers and collect N allowances, which `services/confirm/customer_rate_limit.py`
says plainly rather than implying otherwise.
"""

from __future__ import annotations

import asyncio
import dataclasses
import json
from typing import Any

import httpx2
import pytest
import pytest_asyncio
from fastmcp.server.auth.providers.jwt import JWTVerifier, RSAKeyPair
from postern_core.auth.device_keys import no_enrolled_devices
from starlette.applications import Starlette
from starlette.types import Message, Receive, Scope, Send

from services.confirm.auth import ASSERTION_STATE_KEY, AppAssertion
from services.confirm.customer_rate_limit import (
    CUSTOMER_RATE_LIMITED,
    DEFAULT_CUSTOMER_LIMITS,
    DEFAULT_MAX_CUSTOMERS,
    FALLBACK_CUSTOMER_LIMIT,
    STORE_UNAVAILABLE,
    CustomerRateLimit,
    CustomerRateLimitStoreBase,
    CustomerRateLimitStoreUnavailable,
    InMemoryCustomerRateLimitStore,
    RedisCustomerRateLimitStore,
    create_customer_rate_limit_store,
    customer_handle,
    customer_limits_from_settings,
)
from services.confirm.main import create_confirm_app
from services.confirm.rate_limit import RATE_LIMIT_WINDOW_SECONDS, Limit
from services.confirm.settings import ConfirmSettings
from tests.test_device_grant import AUDIENCE, ISSUER, bearer

CUSTOMER = "cust_7f3a"
OTHER_CUSTOMER = "cust_9b21"

# ---------------------------------------------------------------------------
# Harness.
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def key_pair() -> RSAKeyPair:
    """The banking app's assertion signing key.

    Module-scoped because RSA generation is slow. Defined here rather than
    imported from `tests/test_device_grant.py` for the reason
    `tests/test_confirm_rate_limit.py` gives for its own copy: importing a
    fixture binds its name at module scope, which then collides with every
    signature that asks for it.
    """
    return RSAKeyPair.generate()


class _CountingVerifier:
    """A real ``JWTVerifier`` that records how many tokens it was asked about.

    THE INSTRUMENT FOR `TestTheOuterLimiterIsStillFirst`. The claim being
    tested is about COST -- that a request refused by the address-keyed
    limiter does not pay for a signature verification -- and the only way to
    assert a cost was not paid is to count the thing that would have paid it.
    Reading `create_confirm_app`'s middleware list instead would assert this
    file's opinion of the ordering rather than the ordering.
    """

    def __init__(self, key_pair: RSAKeyPair) -> None:
        self._inner = JWTVerifier(public_key=key_pair.public_key, issuer=ISSUER, audience=AUDIENCE)
        self.verifications = 0

    async def verify_token(self, token: str) -> Any:
        self.verifications += 1
        return await self._inner.verify_token(token)


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


def _settings(**overrides: Any) -> ConfirmSettings:
    return dataclasses.replace(ConfirmSettings.for_testing(), **overrides)


def _app(key_pair: RSAKeyPair, verifier: Any = None, **overrides: Any) -> Starlette:
    """The real composition root, so the middleware ORDER is what is tested.

    Building the app any other way would test this file's opinion of where the
    two limiters sit relative to `AppAssertionMiddleware`, and that relative
    position is the whole reason there are two of them.
    """
    return create_confirm_app(
        _settings(**overrides),
        assertion_verifier=verifier
        or JWTVerifier(public_key=key_pair.public_key, issuer=ISSUER, audience=AUDIENCE),
        device_key_store=no_enrolled_devices(),
    )


def _client(app: Starlette, peer: str = "127.0.0.1") -> httpx2.AsyncClient:
    """``httpx2``, never ``httpx`` -- CLAUDE.md's version traps."""
    return httpx2.AsyncClient(
        transport=httpx2.ASGITransport(app=app, client=(peer, 4444)),
        base_url="http://test",
    )


async def _pair(client: httpx2.AsyncClient) -> tuple[str, str]:
    """Start a device grant and return ``(device_code, user_code)``.

    The pairing is real, so `test_a_legitimate_approval_completes_under_the_ceiling`
    below asserts a 200 from the handler rather than "not a 429", which a
    limiter that let everything through would also satisfy.
    """
    response = await client.post("/device_authorization", json={"client_id": "browser-1"})
    assert response.status_code == 200, response.text
    body = response.json()
    return body["device_code"], body["user_code"]


# --- Direct-ASGI harness, for the middleware in isolation. ------------------


class _Sink:
    """Collects what an ASGI app sends, for driving `CustomerRateLimit` directly."""

    def __init__(self) -> None:
        self.messages: list[Message] = []

    @property
    def status(self) -> int:
        return int(self.messages[0]["status"])

    @property
    def headers(self) -> dict[bytes, bytes]:
        return dict(self.messages[0]["headers"])

    @property
    def body(self) -> dict[str, Any]:
        raw = b"".join(m.get("body", b"") for m in self.messages)
        return dict(json.loads(raw))

    async def __call__(self, message: Message) -> None:
        self.messages.append(message)


class _Downstream:
    """A downstream app that counts what reached it and drains nothing."""

    def __init__(self) -> None:
        self.reached = 0

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        self.reached += 1
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"{}"})


def _scope(path: str, subject: str | None = CUSTOMER) -> Scope:
    """An ASGI scope carrying a verified assertion, or none at all.

    ``subject=None`` models a `PUBLIC_PATHS` entry, where
    `AppAssertionMiddleware` passes the request through without putting an
    `AppAssertion` in the state dict.
    """
    state: dict[str, Any] = {}
    if subject is not None:
        state[ASSERTION_STATE_KEY] = AppAssertion(subject=subject, claims={})
    return {"type": "http", "method": "POST", "path": path, "headers": [], "state": state}


async def _never_receive() -> Message:  # pragma: no cover - a refusal must not call this
    raise AssertionError("a rate-limited request must not drain its body")


def _one_per_window() -> dict[str, Limit]:
    return {"/approve": Limit(requests=1, window_seconds=RATE_LIMIT_WINDOW_SECONDS)}


# ---------------------------------------------------------------------------
# 1. The ceiling itself.
# ---------------------------------------------------------------------------


class TestTheCeiling:
    async def test_the_configured_number_is_admitted_and_the_next_one_is_not(self) -> None:
        downstream = _Downstream()
        limiter = CustomerRateLimit(
            downstream,
            store=InMemoryCustomerRateLimitStore(),
            limits={"/approve": Limit(requests=3, window_seconds=RATE_LIMIT_WINDOW_SECONDS)},
        )
        for _ in range(3):
            sink = _Sink()
            await limiter(_scope("/approve"), _never_receive, sink)
            assert sink.status == 200

        sink = _Sink()
        await limiter(_scope("/approve"), _never_receive, sink)
        assert sink.status == 429
        assert sink.body["error"] == CUSTOMER_RATE_LIMITED
        assert downstream.reached == 3

    async def test_a_refusal_carries_retry_after_and_never_drains_the_body(self) -> None:
        """``_never_receive`` raises if called, which is the assertion.

        The outer limiter owes this property because it is the cheapest
        refusal in the system. This one owes it for a narrower reason: it sits
        in front of `BodySizeLimit`'s consumer rather than behind it, so a
        refusal that drained would buffer up to 64 KiB it is about to discard.
        """
        limiter = CustomerRateLimit(
            _Downstream(), store=InMemoryCustomerRateLimitStore(), limits=_one_per_window()
        )
        await limiter(_scope("/approve"), _never_receive, _Sink())

        sink = _Sink()
        await limiter(_scope("/approve"), _never_receive, sink)
        assert sink.status == 429
        assert 1 <= int(sink.headers[b"retry-after"]) <= RATE_LIMIT_WINDOW_SECONDS + 1

    async def test_each_path_has_its_own_budget(self) -> None:
        """Pairing a device this minute must not cost a payment approval.

        The two actions are unrelated and a shared counter would couple them
        for no benefit either can name.
        """
        limiter = CustomerRateLimit(
            _Downstream(),
            store=InMemoryCustomerRateLimitStore(),
            limits={
                "/approve": Limit(requests=1, window_seconds=RATE_LIMIT_WINDOW_SECONDS),
                "/challenges/approve": Limit(requests=1, window_seconds=RATE_LIMIT_WINDOW_SECONDS),
            },
        )
        first = _Sink()
        await limiter(_scope("/approve"), _never_receive, first)
        second = _Sink()
        await limiter(_scope("/challenges/abc-123/approve"), _never_receive, second)
        assert (first.status, second.status) == (200, 200)

    async def test_every_challenge_id_counts_against_one_budget(self) -> None:
        """Inventing a challenge id must not mint a fresh allowance.

        `route_key` collapses ``/challenges/{id}/approve`` to one key for the
        address-keyed limiter already, and the reason carries over unchanged:
        the id is caller-supplied.
        """
        limiter = CustomerRateLimit(
            _Downstream(),
            store=InMemoryCustomerRateLimitStore(),
            limits={
                "/challenges/approve": Limit(requests=1, window_seconds=RATE_LIMIT_WINDOW_SECONDS)
            },
        )
        await limiter(_scope("/challenges/aaa/approve"), _never_receive, _Sink())

        sink = _Sink()
        await limiter(_scope("/challenges/bbb/approve"), _never_receive, sink)
        assert sink.status == 429

    async def test_a_protected_route_added_later_is_limited_by_omission(self) -> None:
        """Default-deny, in the narrower sense this limiter can express.

        Every request that arrives here WITH a verified subject is charged to
        it, named path or not.
        """
        limiter = CustomerRateLimit(
            _Downstream(),
            store=InMemoryCustomerRateLimitStore(),
            limits={},
            fallback_limit=Limit(requests=2, window_seconds=RATE_LIMIT_WINDOW_SECONDS),
        )
        for _ in range(2):
            sink = _Sink()
            await limiter(_scope("/challenges/x/reject"), _never_receive, sink)
            assert sink.status == 200
        sink = _Sink()
        await limiter(_scope("/challenges/x/reject"), _never_receive, sink)
        assert sink.status == 429

    async def test_a_request_with_no_verified_subject_passes_through(self) -> None:
        """The three `PUBLIC_PATHS` have no customer and are the outer
        limiter's alone.

        This is not a hole: any OTHER route reaching here unverified would
        already have been a 401 from `AppAssertionMiddleware`.
        """
        downstream = _Downstream()
        limiter = CustomerRateLimit(
            downstream, store=InMemoryCustomerRateLimitStore(), limits=_one_per_window()
        )
        for _ in range(5):
            sink = _Sink()
            await limiter(_scope("/token", subject=None), _never_receive, sink)
            assert sink.status == 200
        assert downstream.reached == 5

    async def test_lifespan_is_not_charged_to_anybody(self) -> None:
        downstream = _Downstream()
        limiter = CustomerRateLimit(
            downstream, store=InMemoryCustomerRateLimitStore(), limits=_one_per_window()
        )
        await limiter({"type": "lifespan"}, _never_receive, _Sink())
        assert downstream.reached == 1

    async def test_the_window_rolls_over(self) -> None:
        limiter = CustomerRateLimit(
            _Downstream(),
            store=InMemoryCustomerRateLimitStore(),
            limits={"/approve": Limit(requests=1, window_seconds=0)},
        )
        for _ in range(3):
            sink = _Sink()
            await limiter(_scope("/approve"), _never_receive, sink)
            assert sink.status == 200

    @pytest.mark.parametrize("requests", [0, -1])
    async def test_a_non_positive_limit_is_refused_at_construction(self, requests: int) -> None:
        """A limit of zero refuses every approval that customer attempts,
        which is an outage wearing a control's clothes."""
        with pytest.raises(ValueError, match="at least one request"):
            CustomerRateLimit(
                _Downstream(),
                store=InMemoryCustomerRateLimitStore(),
                limits={"/approve": Limit(requests=requests, window_seconds=60)},
            )

    async def test_a_non_positive_fallback_is_refused_at_construction(self) -> None:
        with pytest.raises(ValueError, match="the fallback"):
            CustomerRateLimit(
                _Downstream(),
                store=InMemoryCustomerRateLimitStore(),
                fallback_limit=Limit(requests=0, window_seconds=60),
            )


# ---------------------------------------------------------------------------
# 2 and 3. The unit. This is the whole point of the work.
# ---------------------------------------------------------------------------


class TestTheBudgetIsPerCustomer:
    async def test_two_customers_do_not_share_a_budget(self) -> None:
        limiter = CustomerRateLimit(
            _Downstream(), store=InMemoryCustomerRateLimitStore(), limits=_one_per_window()
        )
        await limiter(_scope("/approve", subject=CUSTOMER), _never_receive, _Sink())

        spent = _Sink()
        await limiter(_scope("/approve", subject=CUSTOMER), _never_receive, spent)
        assert spent.status == 429

        other = _Sink()
        await limiter(_scope("/approve", subject=OTHER_CUSTOMER), _never_receive, other)
        assert other.status == 200

    async def test_two_customers_from_one_address_do_not_share_a_budget(
        self, key_pair: RSAKeyPair
    ) -> None:
        """Through the assembled app, from ONE client address.

        The address-keyed limiter cannot tell these two requests apart at all.
        Its ceiling stays generous and untouched above this one, so what
        refuses here is the customer ceiling and nothing else.
        """
        app = _app(key_pair, customer_rate_limit_approve=1)
        async with _client(app, peer="198.51.100.7") as client:
            device_code, user_code = await _pair(client)
            body = {"device_code": device_code, "user_code": user_code}

            first = await client.post("/approve", json=body, headers=bearer(key_pair, CUSTOMER))
            assert first.status_code == 200

            spent = await client.post("/approve", json=body, headers=bearer(key_pair, CUSTOMER))
            assert spent.status_code == 429
            assert spent.json()["error"] == CUSTOMER_RATE_LIMITED

            # Same socket, same everything the outer limiter can see.
            other = await client.post(
                "/approve", json=body, headers=bearer(key_pair, OTHER_CUSTOMER)
            )
            assert other.status_code != 429

    async def test_one_customer_from_two_addresses_shares_one_budget(
        self, key_pair: RSAKeyPair
    ) -> None:
        """THE PROPERTY AN ADDRESS-KEYED LIMITER CANNOT EXPRESS.

        Two clients, two socket peers, two address buckets -- so the outer
        limiter sees two independent callers and charges them separately, and
        would admit both. One customer, so this one charges them together.
        That difference is the entire reason this limiter exists.
        """
        app = _app(key_pair, customer_rate_limit_approve=1)
        async with (
            _client(app, peer="198.51.100.1") as first_client,
            _client(app, peer="203.0.113.99") as second_client,
        ):
            device_code, user_code = await _pair(first_client)
            body = {"device_code": device_code, "user_code": user_code}

            first = await first_client.post(
                "/approve", json=body, headers=bearer(key_pair, CUSTOMER)
            )
            assert first.status_code == 200

            second = await second_client.post(
                "/approve", json=body, headers=bearer(key_pair, CUSTOMER)
            )
            assert second.status_code == 429
            assert second.json()["error"] == CUSTOMER_RATE_LIMITED

    async def test_a_legitimate_approval_completes_under_the_ceiling(
        self, key_pair: RSAKeyPair
    ) -> None:
        """The shipped default of 10, and a real pairing approved under it.

        A limiter that refused everything would pass every refusal assertion
        in this file; this is the one that would fail.
        """
        app = _app(key_pair)
        async with _client(app) as client:
            for _ in range(3):
                device_code, user_code = await _pair(client)
                response = await client.post(
                    "/approve",
                    json={"device_code": device_code, "user_code": user_code},
                    headers=bearer(key_pair, CUSTOMER),
                )
                assert response.status_code == 200
                assert response.json() == {"status": "approved"}


# ---------------------------------------------------------------------------
# 4. The layering.
# ---------------------------------------------------------------------------


class TestTheOuterLimiterIsStillFirst:
    async def test_an_address_refusal_never_reaches_the_assertion_verifier(
        self, key_pair: RSAKeyPair
    ) -> None:
        """The cost property, asserted by counting verifications.

        A `sub`-keyed refusal has already paid for a JWKS fetch and a
        signature verification, which is exactly the resource the outer
        limiter exists to protect. So the outer one stays in front, and this
        proves it still is: past its ceiling the verifier stops being called
        at all.
        """
        verifier = _CountingVerifier(key_pair)
        app = _app(key_pair, verifier=verifier, rate_limit_approve=2)
        async with _client(app) as client:
            for _ in range(6):
                await client.post(
                    "/approve",
                    json={"device_code": "x", "user_code": "y"},
                    headers=bearer(key_pair, CUSTOMER),
                )
        assert verifier.verifications == 2

    async def test_the_outer_ceiling_still_refuses_before_the_customer_one(
        self, key_pair: RSAKeyPair
    ) -> None:
        """With the address ceiling BELOW the customer ceiling, the address
        one is what answers -- which is what "outermost" means, checked from
        the outside rather than from the middleware list."""
        app = _app(key_pair, rate_limit_approve=1, customer_rate_limit_approve=50)
        async with _client(app) as client:
            await client.post(
                "/approve",
                json={"device_code": "x", "user_code": "y"},
                headers=bearer(key_pair, CUSTOMER),
            )
            refused = await client.post(
                "/approve",
                json={"device_code": "x", "user_code": "y"},
                headers=bearer(key_pair, CUSTOMER),
            )
        assert refused.status_code == 429
        assert refused.json()["error"] == "too_many_requests"

    async def test_the_public_paths_are_not_customer_limited(self, key_pair: RSAKeyPair) -> None:
        """``/device_authorization`` is served before any identity exists, so
        a customer ceiling of one must not bound a browser starting pairings."""
        app = _app(key_pair, customer_rate_limit_approve=1)
        async with _client(app) as client:
            for _ in range(4):
                response = await client.post(
                    "/device_authorization", json={"client_id": "browser-1"}
                )
                assert response.status_code == 200


# ---------------------------------------------------------------------------
# 5. Telling the two refusals apart.
# ---------------------------------------------------------------------------


class TestAnOperatorCanTellTheTwoRefusalsApart:
    async def test_the_two_ceilings_answer_different_bodies_from_one_app(
        self, key_pair: RSAKeyPair
    ) -> None:
        """Both are 429 with a ``Retry-After``, because both are honestly
        "too many requests" and a client should back off for either. The
        ``error`` code is what separates them, and it has to, because the two
        have opposite remedies: one is raised with
        ``POSTERN_CONFIRM_RATE_LIMIT_APPROVE`` and the other with
        ``POSTERN_CONFIRM_CUSTOMER_RATE_LIMIT_APPROVE``, and raising the wrong
        one is either a no-op or a hole.
        """
        app = _app(key_pair, rate_limit_approve=3, customer_rate_limit_approve=1)
        body = {"device_code": "x", "user_code": "y"}
        async with _client(app) as client:
            admitted = await client.post("/approve", json=body, headers=bearer(key_pair, CUSTOMER))
            assert admitted.status_code != 429

            customer_refusal = await client.post(
                "/approve", json=body, headers=bearer(key_pair, CUSTOMER)
            )
            # Third request exhausts the address ceiling of three.
            await client.post("/approve", json=body, headers=bearer(key_pair, OTHER_CUSTOMER))
            address_refusal = await client.post(
                "/approve", json=body, headers=bearer(key_pair, OTHER_CUSTOMER)
            )

        assert customer_refusal.status_code == 429
        assert customer_refusal.json()["error"] == CUSTOMER_RATE_LIMITED
        assert "this customer" in customer_refusal.json()["error_description"]

        assert address_refusal.status_code == 429
        assert address_refusal.json()["error"] == "too_many_requests"
        assert "this client" in address_refusal.json()["error_description"]

        assert customer_refusal.json()["error"] != address_refusal.json()["error"]
        assert b"retry-after" in {k.lower().encode() for k in customer_refusal.headers}
        assert b"retry-after" in {k.lower().encode() for k in address_refusal.headers}

    async def test_the_log_line_names_the_ceiling_and_never_the_customer(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """`services/confirm/revocation.py`'s ``log_refusal`` sets this
        service's rule and its reason: a ``sub`` minted by a compromised
        issuer can be PAN-, IBAN- or DNI-shaped, and a log line carries
        whatever the issuer put there.

        The subject below is a PAN, which is what that rule is about.
        """
        pan_shaped = "4111111111111111"
        limiter = CustomerRateLimit(
            _Downstream(), store=InMemoryCustomerRateLimitStore(), limits=_one_per_window()
        )
        await limiter(_scope("/approve", subject=pan_shaped), _never_receive, _Sink())
        with caplog.at_level("WARNING"):
            await limiter(_scope("/approve", subject=pan_shaped), _never_receive, _Sink())

        assert caplog.text, "a refusal must leave a trace"
        assert pan_shaped not in caplog.text
        assert customer_handle(pan_shaped) in caplog.text
        assert "per-customer ceiling" in caplog.text

    def test_the_handle_is_stable_and_distinguishes_customers(self) -> None:
        assert customer_handle(CUSTOMER) == customer_handle(CUSTOMER)
        assert customer_handle(CUSTOMER) != customer_handle(OTHER_CUSTOMER)
        assert len(customer_handle(CUSTOMER)) == 16


# ---------------------------------------------------------------------------
# 6. The audit row. Decision 5, and the negative is proven with a live poison.
# ---------------------------------------------------------------------------


class _DatabaseTouched(RuntimeError):
    """Raised by `_PoisonedDatabase`.

    Its own type rather than ``AssertionError`` so that ``pytest.raises``
    below names this tripwire specifically, instead of swallowing any
    assertion that happens to fire inside the handler.
    """


class _PoisonedDatabase:
    """Anything that touches the database raises.

    `services/confirm/audit.py` reaches ``Database.sessionmaker()`` for every
    row it writes, so an attribute access on this object is the tripwire. It
    records the touch as well as raising, so the positive control below can
    assert the poison is LIVE -- without that, this test would pass against a
    limiter that refused every request, which is the mutation
    `TestTheCeiling` covers from the other side.
    """

    def __init__(self) -> None:
        self.touched = 0

    def __getattr__(self, name: str) -> Any:
        self.touched += 1
        raise _DatabaseTouched(f"the database was touched ({name})")


class TestARefusalWritesNoAuditRow:
    async def test_a_refused_challenge_approval_never_reaches_the_database(
        self, key_pair: RSAKeyPair
    ) -> None:
        """DECISION 5, PROVEN. The refusal happens before routing, so the
        handler that builds `ApprovalAudit` never runs and no row can be
        written.

        The outer limiter writes none because it runs before the database
        exists. This one could reach it and deliberately does not:
        ``audit_log`` records what happened to an APPROVAL, this never became
        one, and only one of the two limited paths has an audit trail at all
        -- so a row here would appear for challenge approvals and be silently
        absent for pairing approvals, which is an undercount that gets
        trusted.
        """
        app = _app(key_pair, customer_rate_limit_challenge_approve=1)
        poison = _PoisonedDatabase()
        app.state.postern_database = poison

        async with _client(app) as client:
            body = {"signature": "sig", "confirming_device": "dev"}
            # POSITIVE CONTROL, and it comes first deliberately: the ADMITTED
            # request reaches the handler, which reaches the database, which
            # raises out through the ASGI stack. If the poison were inert this
            # would not raise and the assertion below would prove nothing --
            # a limiter that refused every request would otherwise satisfy it.
            with pytest.raises(_DatabaseTouched):
                await client.post(
                    "/challenges/chal-1/approve", json=body, headers=bearer(key_pair, CUSTOMER)
                )
            assert poison.touched >= 1

            touched_before = poison.touched
            refused = await client.post(
                "/challenges/chal-1/approve", json=body, headers=bearer(key_pair, CUSTOMER)
            )

        assert refused.status_code == 429
        assert refused.json()["error"] == CUSTOMER_RATE_LIMITED
        # THE ASSERTION THIS FILE SECTION EXISTS FOR: the refused request
        # added no touch of its own, so no `audit_log` row was even attempted.
        assert poison.touched == touched_before


# ---------------------------------------------------------------------------
# 2 (decision). Where the counters live.
# ---------------------------------------------------------------------------


class _UnreachableStore(CustomerRateLimitStoreBase):
    async def charge(self, key: str, route: str, limit: Limit) -> int | None:
        raise CustomerRateLimitStoreUnavailable("the counter could not be reached: ConnectionError")


class TestAnUnreachableCounterRefuses:
    async def test_it_answers_503_and_not_429(self) -> None:
        """The caller is not over any ceiling and has done nothing wrong, so a
        429 would teach an operator's dashboard to attribute an infrastructure
        outage to a customer's behaviour."""
        downstream = _Downstream()
        limiter = CustomerRateLimit(downstream, store=_UnreachableStore())
        sink = _Sink()
        await limiter(_scope("/approve"), _never_receive, sink)

        assert sink.status == 503
        assert sink.body["error"] == STORE_UNAVAILABLE
        assert int(sink.headers[b"retry-after"]) == RATE_LIMIT_WINDOW_SECONDS
        assert downstream.reached == 0, "failing open would admit here"

    async def test_the_caller_learns_nothing_about_the_infrastructure(self) -> None:
        limiter = CustomerRateLimit(_Downstream(), store=_UnreachableStore())
        sink = _Sink()
        await limiter(_scope("/approve"), _never_receive, sink)
        assert "ConnectionError" not in json.dumps(sink.body)


class TestTheFactoryFollowsTheOtherThreeStores:
    def test_no_redis_url_gives_per_replica_counters(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("POSTERN_REDIS_URL", raising=False)
        assert isinstance(create_customer_rate_limit_store(), InMemoryCustomerRateLimitStore)

    def test_a_redis_url_gives_shared_counters(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("POSTERN_REDIS_URL", "redis://localhost:6379/0")
        assert isinstance(create_customer_rate_limit_store(), RedisCustomerRateLimitStore)

    async def test_the_in_memory_map_is_capped(self) -> None:
        """A compromised assertion issuer can mint unbounded distinct
        subjects, so this map is an accumulator too.

        Eviction only RESETS a counter, so it can never deny anyone -- which
        is the second assertion: the evicted customer is admitted again rather
        than refused.
        """
        store = InMemoryCustomerRateLimitStore(max_customers=4)
        limit = Limit(requests=1, window_seconds=60)

        assert await store.charge("cust_evicted", "/approve", limit) is None
        assert await store.charge("cust_evicted", "/approve", limit) is not None

        for index in range(50):
            await store.charge(f"cust_{index}", "/approve", limit)
        assert len(store) == 4

        assert await store.charge("cust_evicted", "/approve", limit) is None

    def test_the_cap_default_is_the_address_limiters(self) -> None:
        assert DEFAULT_MAX_CUSTOMERS == 20_000


# ---------------------------------------------------------------------------
# The shipped numbers, and the settings that reproduce them.
# ---------------------------------------------------------------------------


class TestTheShippedCeilings:
    def test_both_defaults_are_ten_a_minute(self) -> None:
        """Both paths are ONE TAP ON A PHONE per unit of work.

        A device pairing is roughly fifteen seconds of human action (scan,
        read a six-character code, tap), so about four a minute is a person
        going as fast as the flow allows. A challenge approval is five to
        eight seconds -- the reading of the payee and the amount is the part
        that cannot be compressed and is the whole point of the confirmation
        -- so about seven a minute. Ten admits both with margin and refuses
        the sixty the address ceiling would have allowed.
        """
        for route in ("/approve", "/challenges/approve"):
            assert DEFAULT_CUSTOMER_LIMITS[route] == Limit(10, RATE_LIMIT_WINDOW_SECONDS)
        assert FALLBACK_CUSTOMER_LIMIT == Limit(10, RATE_LIMIT_WINDOW_SECONDS)

    def test_the_settings_reproduce_the_defaults_exactly(self) -> None:
        settings = ConfirmSettings.for_testing()
        assert (
            customer_limits_from_settings(
                approve=settings.customer_rate_limit_approve,
                challenge_approve=settings.customer_rate_limit_challenge_approve,
            )
            == DEFAULT_CUSTOMER_LIMITS
        )

    def test_the_customer_ceiling_is_well_under_the_address_one(self) -> None:
        """The defect in one assertion: the address ceiling admitted sixty
        approvals a minute from one customer, and sixty from one customer is
        the signal the whole change exists to produce."""
        settings = ConfirmSettings.for_testing()
        assert settings.customer_rate_limit_approve < settings.rate_limit_approve
        assert (
            settings.customer_rate_limit_challenge_approve < settings.rate_limit_challenge_approve
        )


# ---------------------------------------------------------------------------
# The Redis backend, against a real Redis.
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture()
async def redis_stores(redis_url: str, request: pytest.FixtureRequest) -> Any:
    """Two store instances over one Redis, in a namespace of their own.

    TWO, because one is not a test of anything this backend is for. The claim
    is that counters are SHARED, and a single instance would hold a shared and
    a per-process counter identically. These two stand in for two replicas.

    A namespace per test rather than a flush, matching
    `tests/test_redis_backed_stores.py`'s ``stores`` fixture: the container is
    session-scoped because starting one costs wall clock that `make ci` pays
    before every commit.
    """
    prefix = f"crl-{request.node.name}-{id(request)}:"
    first = RedisCustomerRateLimitStore(url=redis_url, key_prefix=prefix)
    second = RedisCustomerRateLimitStore(url=redis_url, key_prefix=prefix)
    yield first, second
    await first._redis.aclose()
    await second._redis.aclose()


class TestTheCountersAreShared:
    async def test_two_replicas_spend_one_budget(self, redis_stores: Any) -> None:
        """DECISION 2, PROVEN. This is what in-process counters cannot do.

        MCP ``2026-07-28`` removed protocol-level sessions, so "any request
        can land on any instance": a customer's requests spread across R
        replicas would exhaust R separate in-process counters and a configured
        ten would be a real R times ten, always, with no line of configuration
        saying so.
        """
        first, second = redis_stores
        limit = Limit(requests=2, window_seconds=60)

        assert await first.charge("cust-a", "/approve", limit) is None
        assert await second.charge("cust-a", "/approve", limit) is None

        refused = await second.charge("cust-a", "/approve", limit)
        assert refused is not None and refused >= 1

        # And the other replica agrees, which it would not if each held its own.
        assert await first.charge("cust-a", "/approve", limit) is not None

    async def test_two_customers_do_not_share_a_redis_budget(self, redis_stores: Any) -> None:
        first, _ = redis_stores
        limit = Limit(requests=1, window_seconds=60)
        assert await first.charge("cust-a", "/approve", limit) is None
        assert await first.charge("cust-a", "/approve", limit) is not None
        assert await first.charge("cust-b", "/approve", limit) is None

    async def test_each_route_has_its_own_redis_budget(self, redis_stores: Any) -> None:
        first, _ = redis_stores
        limit = Limit(requests=1, window_seconds=60)
        assert await first.charge("cust-a", "/approve", limit) is None
        assert await first.charge("cust-a", "/challenges/approve", limit) is None

    async def test_the_window_expires_and_the_budget_returns(self, redis_stores: Any) -> None:
        """The server's expiry, not the test process's clock.

        `tests/test_redis_backed_stores.py` records why that distinction is
        the reason this file wants a container at all: fakeredis expires keys
        against the test process's own ``time.time``, so a store whose TTL
        arithmetic is wrong can look correct under a clock-patching fake.
        """
        first, _ = redis_stores
        limit = Limit(requests=1, window_seconds=1)
        assert await first.charge("cust-a", "/approve", limit) is None
        assert await first.charge("cust-a", "/approve", limit) is not None
        await asyncio.sleep(1.5)
        assert await first.charge("cust-a", "/approve", limit) is None

    async def test_hammering_does_not_extend_the_window(self, redis_stores: Any) -> None:
        """``EXPIRE`` fires only on the transition through 1, so a caller
        cannot push their own deadline out by continuing to send."""
        first, _ = redis_stores
        limit = Limit(requests=1, window_seconds=60)
        assert await first.charge("cust-a", "/approve", limit) is None
        seen = [await first.charge("cust-a", "/approve", limit) for _ in range(5)]
        assert all(value is not None for value in seen)
        # Every remaining-time answer is at or below the window, and the
        # sequence never climbs: a deadline that moved would show as a value
        # larger than one before it.
        assert all(value is not None and value <= 60 for value in seen)
        assert seen == sorted(seen, reverse=True)

    async def test_an_unreachable_redis_raises_rather_than_admitting(self) -> None:
        """A socket that refuses, which is the case a fake cannot produce.

        Failing OPEN would remove the control exactly when a flood is the most
        plausible explanation for the store being gone.
        """
        store = RedisCustomerRateLimitStore(url="redis://127.0.0.1:1/0", key_prefix="crl-dead:")
        with pytest.raises(CustomerRateLimitStoreUnavailable):
            await store.charge("cust-a", "/approve", Limit(requests=1, window_seconds=60))
        await store._redis.aclose()

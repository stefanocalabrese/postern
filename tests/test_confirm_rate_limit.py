"""``services/confirm`` bounds what an unauthenticated caller can accumulate.

TWO CONTROLS, AND THE TESTS ARE SEPARATED THE WAY THE CONTROLS ARE. A rate
limit bounds the ARRIVAL RATE; a store cap bounds the STANDING COST. Neither
substitutes for the other, so neither set of tests below stands in for the
other set.

THE DEFECT, MEASURED. ``create_confirm_app`` driven over ASGI on 2026-09-24,
2,000 ``POST /device_authorization`` calls with no credential of any kind.
The "padded" column carries a body just under the 64 KiB ceiling
`services/confirm/body_limit.py` enforces, which is the shape that was
measured before any of this existed; the "realistic" column carries a body no
field bound can object to, so the rate limit is the only thing in its way:

==============================  =============  ============  =============
                                before         after,        after,
                                (padded)       padded        realistic
==============================  =============  ============  =============
requests answered 200           2,000          0             60
device codes held               2,000          0             60
device code store, deep size    128,990,755 B  64 B          29,034 B
RSS delta                       131,252,224 B  409,600 B     98,304 B
==============================  =============  ============  =============

A padded body is now refused twice over: the rate limit answers 429 to 1,940
of the 2,000 without reading a body at all, and the 60 it admits are refused
400 by the ``scopes`` ceiling before a code is created. Nothing reaches the
store. A realistic body reaches it 60 times, which is the limit, and costs
29,034 bytes instead of 128,990,755.

Three separate facts produced that first column, and each one has its own
tests here:

1. Nothing limited the rate, so all 2,000 were admitted.
2. Nothing capped the store, so all 2,000 were kept.
3. Nothing bounded ``scopes``, so each one cost 64,495 bytes instead of the
   1,633 a realistic code costs. The body limit in front of this service does
   not bound that -- it counts wire bytes, and 24,000 bytes of JSON array
   parse to 67,252 bytes of Python objects.

AND ONE THE BRIEF DID NOT CLAIM, found while measuring: the in-memory store
had no reaper at all. The 900-second lifetime is ``SETEX`` on the Redis
backend and was never a property of the in-memory one, so a caller who created
codes and never polled leaked them for the life of the process rather than for
fifteen minutes. `TestTheInMemoryStoreNowReaps` pins the fix.

WHAT THESE TESTS DELIBERATELY DO NOT CLAIM. They do not show this service is
safe from a distributed flood, because it is not and nothing in this
repository could make it so. They show the failure is now bounded: memory
stops growing and the refusal is explicit. `services/confirm/rate_limit.py`'s
docstring names the infrastructure that would be needed for the rest.
"""

from __future__ import annotations

import asyncio
import dataclasses
import gc
import sys
from typing import Any

import httpx2
import pytest
from fastmcp.server.auth.providers.jwt import JWTVerifier, RSAKeyPair
from postern_core.auth.device_codes import (
    DEFAULT_MAX_DEVICE_CODES,
    DeviceCodeStoreFull,
    InMemoryDeviceCodeStore,
)
from postern_core.auth.device_keys import no_enrolled_devices
from postern_core.net import IPV6_BUCKET_PREFIX_BITS, client_ip, ip_bucket
from starlette.applications import Starlette
from starlette.types import Message, Receive, Scope, Send

from services.confirm.main import create_confirm_app
from services.confirm.rate_limit import (
    DEFAULT_LIMITS,
    FALLBACK_LIMIT,
    RATE_LIMIT_WINDOW_SECONDS,
    UNATTRIBUTED,
    Limit,
    RateLimit,
    limits_from_settings,
    route_key,
)
from services.confirm.settings import ConfirmSettings
from tests.test_device_grant import AUDIENCE, ISSUER, bearer

# ---------------------------------------------------------------------------
# Harness.
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def key_pair() -> RSAKeyPair:
    """The banking app's assertion signing key, for the end-to-end flows.

    Module-scoped because RSA generation is slow and every test here that
    needs a valid assertion can share one. Defined rather than imported from
    `tests/test_device_grant.py`: importing a fixture binds its name at
    module scope, which then collides with every signature that asks for it.
    """
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


def _settings(**overrides: Any) -> ConfirmSettings:
    return dataclasses.replace(ConfirmSettings.for_testing(), **overrides)


def _app(keys: RSAKeyPair, **overrides: Any) -> Starlette:
    """The real composition root, so the middleware ORDER is what is tested.

    Building the app any other way would test this file's opinion of where
    the rate limit sits, and its position -- ahead of the body limit and
    therefore ahead of authentication -- is half of what it is for.
    """
    return create_confirm_app(
        _settings(**overrides),
        assertion_verifier=JWTVerifier(
            public_key=keys.public_key, issuer=ISSUER, audience=AUDIENCE
        ),
        device_key_store=no_enrolled_devices(),
    )


def _client(app: Starlette, peer: str = "127.0.0.1") -> httpx2.AsyncClient:
    return httpx2.AsyncClient(
        transport=httpx2.ASGITransport(app=app, client=(peer, 4444)),
        base_url="http://test",
    )


def _deep_size(obj: Any, seen: set[int] | None = None) -> int:
    """Recursive ``sys.getsizeof``, for the before/after memory table."""
    seen = seen if seen is not None else set()
    if id(obj) in seen:
        return 0
    seen.add(id(obj))
    size = sys.getsizeof(obj)
    if isinstance(obj, dict):
        for key, value in obj.items():
            size += _deep_size(key, seen) + _deep_size(value, seen)
    elif isinstance(obj, list | tuple | set | frozenset):
        for item in obj:
            size += _deep_size(item, seen)
    elif hasattr(obj, "__dict__"):
        size += _deep_size(vars(obj), seen)
    return size


class _Sink:
    """Collects what an ASGI app sends, for driving `RateLimit` directly."""

    def __init__(self) -> None:
        self.messages: list[Message] = []

    async def __call__(self, message: Message) -> None:
        self.messages.append(message)

    @property
    def status(self) -> int:
        return int(self.messages[0]["status"])

    @property
    def headers(self) -> dict[bytes, bytes]:
        return dict(self.messages[0]["headers"])


class _Downstream:
    """A downstream app that counts what reached it and drains nothing."""

    def __init__(self) -> None:
        self.reached = 0

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        self.reached += 1
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"{}"})


def _scope(path: str, *, peer: str | None = "203.0.113.9", forwarded: str | None = None) -> Scope:
    headers: list[tuple[bytes, bytes]] = []
    if forwarded is not None:
        headers.append((b"x-forwarded-for", forwarded.encode()))
    return {
        "type": "http",
        "method": "POST",
        "path": path,
        "headers": headers,
        "client": None if peer is None else (peer, 5555),
    }


async def _never_receive() -> Message:  # pragma: no cover - a refusal must not call this
    raise AssertionError("a rate-limited request must not drain its body")


# ---------------------------------------------------------------------------
# The shared address derivation (`postern_core.net`).
#
# It lives in `postern_core` and not beside either caller because
# `.importlinter` forbids the two services from importing each other, and a
# second copy of a hop-counted address derivation is the shape
# `services/api/middleware/audit.py` records going wrong once already, when
# three copies of `_scrub` existed and the weakest sat on the money path.
# ---------------------------------------------------------------------------


class TestClientAddressDerivation:
    def test_zero_hops_uses_the_socket_peer_and_ignores_the_header(self) -> None:
        """The default trusts the header for nothing."""
        assert (
            client_ip(forwarded="9.9.9.9", peer_host="203.0.113.7", trusted_proxy_hops=0)
            == "203.0.113.7"
        )

    def test_one_hop_takes_the_rightmost_entry_not_the_leftmost(self) -> None:
        """The leftmost entry is the one the caller writes.

        Reading it would let an attacker pin their apparent bucket, or rotate
        it to get an unlimited number of budgets from one address.
        """
        assert (
            client_ip(forwarded="9.9.9.9, 203.0.113.7", peer_host="10.0.0.1", trusted_proxy_hops=1)
            == "203.0.113.7"
        )

    def test_a_header_shorter_than_the_trusted_hops_yields_nothing(self) -> None:
        assert client_ip(forwarded="9.9.9.9", peer_host="10.0.0.1", trusted_proxy_hops=2) is None

    def test_an_absent_header_under_trusted_hops_yields_nothing(self) -> None:
        assert client_ip(forwarded=None, peer_host="10.0.0.1", trusted_proxy_hops=1) is None

    def test_an_unparseable_address_yields_nothing(self) -> None:
        assert client_ip(forwarded="not-an-address", peer_host=None, trusted_proxy_hops=1) is None

    def test_no_peer_and_no_hops_yields_nothing(self) -> None:
        assert client_ip(forwarded=None, peer_host=None, trusted_proxy_hops=0) is None

    def test_spellings_of_one_address_canonicalise_to_one(self) -> None:
        derived = {
            client_ip(forwarded=spelling, peer_host=None, trusted_proxy_hops=1)
            for spelling in (
                "2001:db8::1",
                "2001:0db8:0000:0000:0000:0000:0000:0001",
                "2001:DB8::1",
            )
        }
        assert derived == {"2001:db8::1"}

    def test_a_negative_hop_count_is_refused(self) -> None:
        with pytest.raises(ValueError, match="trusted_proxy_hops"):
            client_ip(forwarded=None, peer_host="10.0.0.1", trusted_proxy_hops=-1)


class TestAddressBucketing:
    def test_an_ipv4_address_is_its_own_bucket(self) -> None:
        assert ip_bucket("203.0.113.7") == "203.0.113.7"
        assert ip_bucket("203.0.113.7") != ip_bucket("203.0.113.8")

    def test_ipv6_addresses_in_one_slash_64_share_a_bucket(self) -> None:
        """Without this, per-address limiting is free to defeat.

        A single residential or mobile allocation is a /64 or larger, so
        counting each address as an identity hands one customer 2**64 of
        them.
        """
        assert IPV6_BUCKET_PREFIX_BITS == 64
        first = ip_bucket("2001:db8:1:2::1")
        last = ip_bucket("2001:db8:1:2:ffff:ffff:ffff:ffff")
        assert first == last == "2001:db8:1:2::/64"

    def test_different_slash_64s_are_different_buckets(self) -> None:
        assert ip_bucket("2001:db8:1:2::1") != ip_bucket("2001:db8:1:3::1")


# ---------------------------------------------------------------------------
# The rate limit: arrival rate.
# ---------------------------------------------------------------------------


class TestTheLimitRefusesAtTheChosenRate:
    async def test_the_configured_number_is_admitted_and_the_next_is_not(self) -> None:
        downstream = _Downstream()
        limiter = RateLimit(
            downstream, limits={"/device_authorization": Limit(requests=5, window_seconds=60)}
        )

        for _ in range(5):
            sink = _Sink()
            await limiter(_scope("/device_authorization"), _never_receive, sink)
            assert sink.status == 200

        sink = _Sink()
        await limiter(_scope("/device_authorization"), _never_receive, sink)
        assert sink.status == 429
        assert downstream.reached == 5

    async def test_a_refusal_carries_retry_after_and_never_drains_the_body(self) -> None:
        """``_never_receive`` raises if called, which is the assertion.

        Behind `BodySizeLimit` every refusal would still cost a 64 KiB
        buffer; that buffer is the resource a flood is spending.
        """
        limiter = RateLimit(
            _Downstream(), limits={"/approve": Limit(requests=1, window_seconds=60)}
        )
        await limiter(_scope("/approve"), _never_receive, _Sink())

        sink = _Sink()
        await limiter(_scope("/approve"), _never_receive, sink)
        assert sink.status == 429
        assert 1 <= int(sink.headers[b"retry-after"]) <= 61

    async def test_the_token_endpoint_is_refused_in_rfc_8628_vocabulary(self) -> None:
        """400 ``slow_down``, not 429.

        A conforming device-grant client already reacts to ``slow_down`` by
        lengthening its polling interval, which is the behaviour wanted. It
        has no defined reaction to a 429, and RFC 6749 §5.2 token-endpoint
        errors carry a 400.
        """
        limiter = RateLimit(_Downstream(), limits={"/token": Limit(requests=1, window_seconds=60)})
        await limiter(_scope("/token"), _never_receive, _Sink())

        sink = _Sink()
        await limiter(_scope("/token"), _never_receive, sink)
        assert sink.status == 400
        body = b"".join(m.get("body", b"") for m in sink.messages)
        assert b'"slow_down"' in body

    async def test_each_path_has_its_own_budget(self) -> None:
        limiter = RateLimit(
            _Downstream(),
            limits={
                "/device_authorization": Limit(requests=1, window_seconds=60),
                "/approve": Limit(requests=1, window_seconds=60),
            },
        )
        first = _Sink()
        await limiter(_scope("/device_authorization"), _never_receive, first)
        second = _Sink()
        await limiter(_scope("/approve"), _never_receive, second)
        assert (first.status, second.status) == (200, 200)

    async def test_an_unlisted_path_is_limited_by_omission(self) -> None:
        """Default-deny on paths, the direction ``PUBLIC_PATHS`` set.

        A route added to this service tomorrow is rate-limited without anyone
        remembering to add it here.
        """
        limiter = RateLimit(_Downstream(), fallback_limit=Limit(requests=2, window_seconds=60))
        for _ in range(2):
            sink = _Sink()
            await limiter(_scope("/some/route/added/later"), _never_receive, sink)
            assert sink.status == 200
        sink = _Sink()
        await limiter(_scope("/some/route/added/later"), _never_receive, sink)
        assert sink.status == 429

    async def test_the_window_rolls_over(self) -> None:
        limiter = RateLimit(_Downstream(), limits={"/approve": Limit(requests=1, window_seconds=0)})
        for _ in range(3):
            sink = _Sink()
            await limiter(_scope("/approve"), _never_receive, sink)
            assert sink.status == 200

    async def test_a_negative_hop_count_is_refused_at_construction(self) -> None:
        with pytest.raises(ValueError, match="trusted_proxy_hops"):
            RateLimit(_Downstream(), trusted_proxy_hops=-1)


class TestTheBudgetIsPerAddressBucket:
    async def test_two_ipv4_addresses_do_not_share_a_budget(self) -> None:
        limiter = RateLimit(
            _Downstream(), limits={"/approve": Limit(requests=1, window_seconds=60)}
        )
        await limiter(_scope("/approve", peer="198.51.100.1"), _never_receive, _Sink())

        sink = _Sink()
        await limiter(_scope("/approve", peer="198.51.100.2"), _never_receive, sink)
        assert sink.status == 200

    async def test_two_ipv6_addresses_in_one_slash_64_do_share_a_budget(self) -> None:
        """The control this bucketing exists for.

        Without it, spending a budget and then moving one bit along inside
        the same allocation costs an attacker nothing.
        """
        limiter = RateLimit(
            _Downstream(), limits={"/approve": Limit(requests=1, window_seconds=60)}
        )
        await limiter(_scope("/approve", peer="2001:db8:5:5::1"), _never_receive, _Sink())

        sink = _Sink()
        await limiter(_scope("/approve", peer="2001:db8:5:5::2"), _never_receive, sink)
        assert sink.status == 429

    async def test_traffic_with_no_derivable_address_shares_one_budget(self) -> None:
        """ "The limiter could not identify you" must not be the cheapest way
        to avoid the limiter."""
        limiter = RateLimit(
            _Downstream(),
            trusted_proxy_hops=2,
            limits={"/approve": Limit(requests=1, window_seconds=60)},
        )
        await limiter(
            _scope("/approve", peer="198.51.100.1", forwarded="9.9.9.9"), _never_receive, _Sink()
        )

        sink = _Sink()
        await limiter(
            _scope("/approve", peer="198.51.100.2", forwarded="8.8.8.8"), _never_receive, sink
        )
        assert sink.status == 429
        assert UNATTRIBUTED == "-"

    async def test_a_spoofed_forwarded_header_cannot_buy_a_fresh_budget(self) -> None:
        """One trusted hop, so the trusted entry is the rightmost.

        The caller varies the leftmost entry, which is theirs to write, and
        gets no new budget for it.
        """
        limiter = RateLimit(
            _Downstream(),
            trusted_proxy_hops=1,
            limits={"/approve": Limit(requests=1, window_seconds=60)},
        )
        await limiter(
            _scope("/approve", peer="10.0.0.1", forwarded="1.1.1.1, 198.51.100.7"),
            _never_receive,
            _Sink(),
        )

        sink = _Sink()
        await limiter(
            _scope("/approve", peer="10.0.0.1", forwarded="2.2.2.2, 198.51.100.7"),
            _never_receive,
            sink,
        )
        assert sink.status == 429


class TestTheChallengeApproveBudgetCannotBeReset:
    def test_every_challenge_id_counts_against_one_key(self) -> None:
        """Per-id counters would let a caller mint a budget by inventing an id.

        The same reason `services/confirm/device_auth.py` refuses to key
        anything on ``DeviceCode.client_id``.
        """
        assert route_key("/challenges/chal_a/approve") == "/challenges/approve"
        assert route_key("/challenges/chal_b/approve") == "/challenges/approve"
        assert route_key("/challenges/approve") in DEFAULT_LIMITS

    async def test_two_challenge_ids_share_a_budget(self) -> None:
        limiter = RateLimit(
            _Downstream(), limits={"/challenges/approve": Limit(requests=1, window_seconds=60)}
        )
        await limiter(_scope("/challenges/chal_a/approve"), _never_receive, _Sink())

        sink = _Sink()
        await limiter(_scope("/challenges/chal_b/approve"), _never_receive, sink)
        assert sink.status == 429


class TestThePairingCapIsASecondControl:
    async def test_a_bucket_is_capped_on_pairings_as_well_as_on_rate(self) -> None:
        """60/min over a 900s lifetime is 900 codes from one address, 9% of
        the store cap: eleven addresses would fill it. The pairing cap makes
        it fifty."""
        limiter = RateLimit(
            _Downstream(),
            limits={"/device_authorization": Limit(requests=1_000, window_seconds=60)},
            pairing_limit=Limit(requests=3, window_seconds=900),
        )
        for _ in range(3):
            sink = _Sink()
            await limiter(_scope("/device_authorization"), _never_receive, sink)
            assert sink.status == 200

        sink = _Sink()
        await limiter(_scope("/device_authorization"), _never_receive, sink)
        assert sink.status == 429
        assert int(sink.headers[b"retry-after"]) > 60

    async def test_the_pairing_cap_does_not_touch_other_paths(self) -> None:
        limiter = RateLimit(
            _Downstream(),
            limits={"/device_authorization": Limit(requests=1_000, window_seconds=60)},
            pairing_limit=Limit(requests=1, window_seconds=900),
        )
        await limiter(_scope("/device_authorization"), _never_receive, _Sink())
        refused = _Sink()
        await limiter(_scope("/device_authorization"), _never_receive, refused)
        assert refused.status == 429

        approve = _Sink()
        await limiter(_scope("/approve"), _never_receive, approve)
        assert approve.status == 200


class TestTheLimiterIsItselfBounded:
    async def test_the_bucket_map_stops_growing(self) -> None:
        """The trap in fixing an accumulation defect.

        A map keyed by client address is exactly the accumulator this task
        exists to close, and an attacker rotating addresses is the traffic
        this middleware attracts.
        """
        limiter = RateLimit(_Downstream(), max_buckets=4)
        for octet in range(200):
            await limiter(
                _scope("/approve", peer=f"198.51.100.{octet % 256}"), _never_receive, _Sink()
            )
            await limiter(
                _scope("/approve", peer=f"203.0.113.{octet % 256}"), _never_receive, _Sink()
            )

        assert len(limiter._buckets) == 4
        assert limiter._buckets.evictions > 0

    async def test_eviction_resets_a_counter_and_never_denies(self) -> None:
        """Eviction is safe here for the reason it is NOT safe in the store.

        Dropping a limiter entry only forgets a count; dropping a device code
        destroys a pairing in flight.
        """
        limiter = RateLimit(
            _Downstream(),
            max_buckets=1,
            limits={"/approve": Limit(requests=1, window_seconds=60)},
        )
        await limiter(_scope("/approve", peer="198.51.100.1"), _never_receive, _Sink())
        await limiter(_scope("/approve", peer="198.51.100.2"), _never_receive, _Sink())

        sink = _Sink()
        await limiter(_scope("/approve", peer="198.51.100.1"), _never_receive, sink)
        assert sink.status == 200


# ---------------------------------------------------------------------------
# The store cap: standing cost.
# ---------------------------------------------------------------------------


class TestTheStoreRefusesWhenFull:
    async def test_creation_past_the_cap_raises(self) -> None:
        store = InMemoryDeviceCodeStore(max_codes=3)
        for _ in range(3):
            await store.create_device_code(
                client_id="c", scopes="s", verification_uri="https://x.invalid/v"
            )

        with pytest.raises(DeviceCodeStoreFull) as caught:
            await store.create_device_code(
                client_id="c", scopes="s", verification_uri="https://x.invalid/v"
            )
        assert caught.value.held == 3
        assert caught.value.cap == 3

    async def test_an_expired_code_is_swept_before_the_cap_is_consulted(self) -> None:
        """Refusing while holding a store full of codes nobody can use would
        be a denial of service this service performs on itself."""
        store = InMemoryDeviceCodeStore(max_codes=2)
        for _ in range(2):
            await store.create_device_code(
                client_id="c",
                scopes="s",
                verification_uri="https://x.invalid/v",
                expires_in=1,
            )
        await asyncio.sleep(1.1)

        fresh = await store.create_device_code(
            client_id="c", scopes="s", verification_uri="https://x.invalid/v"
        )
        assert await store.get_device_code(fresh.device_code) is not None
        assert len(store._codes) == 1

    async def test_a_pairing_in_flight_survives_a_full_store(self) -> None:
        """REFUSE, NOT EVICT, and this is the case that decides it.

        Eviction aimed by age lands on the customer who has already completed
        identity verification and is waiting for the browser's next poll.
        They would see a hang with no explanation and have to start over.
        """
        store = InMemoryDeviceCodeStore(max_codes=2)
        in_flight = await store.create_device_code(
            client_id="browser", scopes="s", verification_uri="https://x.invalid/v"
        )
        await store.create_device_code(
            client_id="flood", scopes="s", verification_uri="https://x.invalid/v"
        )

        for _ in range(10):
            with pytest.raises(DeviceCodeStoreFull):
                await store.create_device_code(
                    client_id="flood", scopes="s", verification_uri="https://x.invalid/v"
                )

        assert await store.get_device_code(in_flight.device_code) is not None

    async def test_the_default_cap_is_the_measured_one(self) -> None:
        assert DEFAULT_MAX_DEVICE_CODES == 10_000
        assert ConfirmSettings.for_testing().max_device_codes == DEFAULT_MAX_DEVICE_CODES


class TestTheInMemoryStoreNowReaps:
    async def test_an_expired_code_does_not_outlive_the_process(self) -> None:
        """Measured before the reaper: a code created with ``expires_in=1``
        was still in ``_codes`` after it reported ``is_expired`` true, because
        the only removals were a ``/token`` poll finding it expired or three
        wrong pairing codes. A caller who never polled leaked it forever."""
        store = InMemoryDeviceCodeStore()
        stale = await store.create_device_code(
            client_id="c", scopes="s", verification_uri="https://x.invalid/v", expires_in=1
        )
        await asyncio.sleep(1.1)
        assert len(store._codes) == 1

        await store.create_device_code(
            client_id="c", scopes="s", verification_uri="https://x.invalid/v"
        )
        assert stale.device_code not in store._codes

    async def test_a_live_code_is_not_swept(self) -> None:
        store = InMemoryDeviceCodeStore()
        live = await store.create_device_code(
            client_id="c", scopes="s", verification_uri="https://x.invalid/v", expires_in=900
        )
        for _ in range(20):
            await store.create_device_code(
                client_id="c", scopes="s", verification_uri="https://x.invalid/v"
            )
        assert await store.get_device_code(live.device_code) is not None

    async def test_a_revoked_code_leaves_no_entry_the_sweep_trips_on(self) -> None:
        """Lazy deletion: the heap keeps an entry the dict no longer has."""
        store = InMemoryDeviceCodeStore()
        code = await store.create_device_code(
            client_id="c", scopes="s", verification_uri="https://x.invalid/v", expires_in=1
        )
        await store.revoke_device_code(code.device_code)
        await asyncio.sleep(1.1)

        survivor = await store.create_device_code(
            client_id="c", scopes="s", verification_uri="https://x.invalid/v"
        )
        assert await store.get_device_code(survivor.device_code) is not None

    async def test_an_expired_code_still_reads_back_until_a_sweep_runs(self) -> None:
        """``get_device_code`` is not expiry-filtered, on purpose.

        ``token_endpoint`` reads ``is_expired`` to answer RFC 8628's
        ``expired_token``; filtering here would turn that into
        ``invalid_grant``, telling a legitimate browser its code was never
        real rather than that it timed out.
        """
        store = InMemoryDeviceCodeStore()
        code = await store.create_device_code(
            client_id="c", scopes="s", verification_uri="https://x.invalid/v", expires_in=1
        )
        await asyncio.sleep(1.1)
        found = await store.get_device_code(code.device_code)
        assert found is not None
        assert found.is_expired


# ---------------------------------------------------------------------------
# What one device code is allowed to cost.
# ---------------------------------------------------------------------------


class TestTheStoredFieldsAreBounded:
    async def test_an_oversized_scopes_string_is_refused(self, key_pair: RSAKeyPair) -> None:
        """40x of the measured standing cost was this one field."""
        app = _app(key_pair, max_scopes_length=64)
        async with _client(app) as client:
            resp = await client.post(
                "/device_authorization", json={"client_id": "b", "scopes": "s" * 65}
            )
        assert resp.status_code == 400
        assert resp.json()["error"] == "invalid_scope"
        assert len(app.state.device_code_store._codes) == 0

    async def test_an_oversized_client_id_is_refused(self, key_pair: RSAKeyPair) -> None:
        app = _app(key_pair, max_client_id_length=32)
        async with _client(app) as client:
            resp = await client.post("/device_authorization", json={"client_id": "b" * 33})
        assert resp.status_code == 400
        assert resp.json()["error"] == "invalid_request"

    async def test_the_boundary_length_is_admitted(self, key_pair: RSAKeyPair) -> None:
        app = _app(key_pair, max_scopes_length=64)
        async with _client(app) as client:
            resp = await client.post(
                "/device_authorization", json={"client_id": "b", "scopes": "s" * 64}
            )
        assert resp.status_code == 200

    async def test_a_non_string_scopes_is_refused(self, key_pair: RSAKeyPair) -> None:
        """The body limit counts wire bytes; the store holds parsed objects.

        24,000 bytes of JSON array parse to 67,252 bytes of Python objects,
        so a byte ceiling in front of this service never bounded this.
        """
        app = _app(key_pair)
        async with _client(app) as client:
            resp = await client.post(
                "/device_authorization", json={"client_id": "b", "scopes": [0] * 2000}
            )
        assert resp.status_code == 400
        assert len(app.state.device_code_store._codes) == 0

    async def test_a_non_string_client_id_is_refused(self, key_pair: RSAKeyPair) -> None:
        app = _app(key_pair)
        async with _client(app) as client:
            resp = await client.post("/device_authorization", json={"client_id": {"a": 1}})
        assert resp.status_code == 400

    async def test_the_default_scopes_are_well_inside_the_ceiling(self) -> None:
        settings = ConfirmSettings.for_testing()
        assert len("accounts:read transactions:read cards:read") < settings.max_scopes_length


class TestAMalformedBodyIsFourHundredNotFiveHundred:
    async def test_invalid_json_is_refused(self, key_pair: RSAKeyPair) -> None:
        """Public endpoint, and ``await request.json()`` sat bare until now.

        The identical defect was fixed one file over in
        `services/confirm/callback.py`.
        """
        app = _app(key_pair)
        async with _client(app) as client:
            resp = await client.post(
                "/device_authorization",
                content=b"{not json",
                headers={"content-type": "application/json"},
            )
        assert resp.status_code == 400

    async def test_a_json_array_body_is_refused(self, key_pair: RSAKeyPair) -> None:
        """``.get`` on a list is an ``AttributeError``, which was a 500."""
        app = _app(key_pair)
        async with _client(app) as client:
            resp = await client.post(
                "/device_authorization",
                content=b"[1, 2, 3]",
                headers={"content-type": "application/json"},
            )
        assert resp.status_code == 400

    async def test_an_empty_json_body_is_refused(self, key_pair: RSAKeyPair) -> None:
        app = _app(key_pair)
        async with _client(app) as client:
            resp = await client.post(
                "/device_authorization",
                content=b"",
                headers={"content-type": "application/json"},
            )
        assert resp.status_code == 400


# ---------------------------------------------------------------------------
# End to end, through the assembled app.
# ---------------------------------------------------------------------------


class TestThroughTheAssembledApp:
    async def test_the_padded_flood_reaches_the_store_not_at_all(
        self, key_pair: RSAKeyPair
    ) -> None:
        """The exact shape that was measured, and it no longer stores a byte.

        2,000 unauthenticated requests, each carrying a body just under the
        64 KiB ceiling `services/confirm/body_limit.py` enforces. Before:
        2,000 admitted, 2,000 codes, 128,990,755 bytes held, 64,495 bytes per
        code. The padding lived in ``scopes``, so the field bound refuses it
        before the rate limit is even the reason.
        """
        app = _app(key_pair)
        settings: ConfirmSettings = app.state.settings
        padded = "a" * (settings.max_body_bytes - 2048)

        statuses: list[int] = []
        async with _client(app) as client:
            for _ in range(2_000):
                resp = await client.post(
                    "/device_authorization", json={"client_id": "b", "scopes": padded}
                )
                statuses.append(resp.status_code)

        # Both controls are visible, in the order they sit in the stack: the
        # rate limit admits its allowance and refuses the rest without
        # reading a body at all, and every request it DOES admit is then
        # refused by the field bound. Neither is doing the other's job.
        limit = DEFAULT_LIMITS["/device_authorization"].requests
        assert statuses[:limit] == [400] * limit
        assert set(statuses[limit:]) == {429}
        assert len(app.state.device_code_store._codes) == 0

    async def test_the_realistic_flood_is_bounded_by_the_rate_limit(
        self, key_pair: RSAKeyPair
    ) -> None:
        """The same 2,000 requests with a body no bound can object to.

        This is the arrival-rate half on its own: every request is
        well-formed and inside every field ceiling, so the only thing
        standing between it and 2,000 stored codes is the limit.
        """
        app = _app(key_pair)

        admitted = 0
        async with _client(app) as client:
            for _ in range(2_000):
                resp = await client.post("/device_authorization", json={"client_id": "b"})
                if resp.status_code == 200:
                    admitted += 1

        held = len(app.state.device_code_store._codes)
        assert admitted == DEFAULT_LIMITS["/device_authorization"].requests
        assert held == admitted
        assert _deep_size(app.state.device_code_store._codes) < 200_000

    async def test_a_legitimate_pairing_completes_under_the_limit(
        self, key_pair: RSAKeyPair
    ) -> None:
        """The control must not break the flow it protects.

        A full device pairing: the browser starts one, the operator's app
        approves it with a verified assertion, the browser exchanges it for a
        read token. Three requests, nowhere near any limit.
        """
        app = _app(key_pair)
        async with _client(app) as client:
            start = await client.post("/device_authorization", json={"client_id": "browser-1"})
            assert start.status_code == 200
            device = start.json()

            approved = await client.post(
                "/approve",
                json={"device_code": device["device_code"], "user_code": device["user_code"]},
                headers=bearer(key_pair),
            )
            assert approved.status_code == 200

            exchanged = await client.post(
                "/token",
                data={"grant_type": "device_code", "device_code": device["device_code"]},
            )

        assert exchanged.status_code == 200
        assert exchanged.json()["token_type"] == "Bearer"  # noqa: S105
        assert "access_token" in exchanged.json()
        assert "write_token" not in exchanged.json()

    async def test_a_legitimate_pairing_still_completes_while_another_bucket_floods(
        self, key_pair: RSAKeyPair
    ) -> None:
        """One address exhausting its budget must not reach another's."""
        app = _app(key_pair, trusted_proxy_hops=1)
        async with _client(app) as flooder:
            for _ in range(120):
                await flooder.post(
                    "/device_authorization",
                    json={"client_id": "flood"},
                    headers={"X-Forwarded-For": "198.51.100.66"},
                )

            customer = {"X-Forwarded-For": "203.0.113.5"}
            start = await flooder.post(
                "/device_authorization", json={"client_id": "browser-1"}, headers=customer
            )
            assert start.status_code == 200
            device = start.json()

            approved = await flooder.post(
                "/approve",
                json={"device_code": device["device_code"], "user_code": device["user_code"]},
                headers={**bearer(key_pair), **customer},
            )
            assert approved.status_code == 200

            exchanged = await flooder.post(
                "/token",
                data={"grant_type": "device_code", "device_code": device["device_code"]},
                headers=customer,
            )
        assert exchanged.status_code == 200

    async def test_a_full_store_answers_retryable_and_leaves_pairings_alone(
        self, key_pair: RSAKeyPair
    ) -> None:
        app = _app(key_pair, max_device_codes=2)
        async with _client(app) as client:
            first = await client.post("/device_authorization", json={"client_id": "browser-1"})
            await client.post("/device_authorization", json={"client_id": "browser-2"})
            full = await client.post("/device_authorization", json={"client_id": "browser-3"})

        assert first.status_code == 200
        assert full.status_code == 503
        assert full.json()["error"] == "temporarily_unavailable"
        assert int(full.headers["retry-after"]) == app.state.settings.device_code_ttl_seconds
        # Refused, not evicted: the pairing already in flight is untouched.
        store = app.state.device_code_store
        assert await store.get_device_code(first.json()["device_code"]) is not None

    async def test_the_rate_limit_sits_in_front_of_authentication(
        self, key_pair: RSAKeyPair
    ) -> None:
        """A flood of unauthenticated approvals must not each cost a JWKS
        fetch and a signature verification."""
        app = _app(key_pair)
        limit = DEFAULT_LIMITS["/challenges/approve"].requests
        statuses = []
        async with _client(app) as client:
            for _ in range(limit + 5):
                resp = await client.post("/challenges/chal_x/approve", json={})
                statuses.append(resp.status_code)

        assert statuses[0] == 401
        assert statuses[-1] == 429


class TestTheSlowDownInteraction:
    async def test_the_per_code_slow_down_still_fires_under_the_ip_limit(
        self, key_pair: RSAKeyPair
    ) -> None:
        """Two controls, keyed differently, and they agree in kind.

        The per-code one enforces RFC 8628's 5-second interval for ONE
        pairing; the per-bucket one bounds an address across every pairing.
        A client honouring either honours both.
        """
        app = _app(key_pair)
        async with _client(app) as client:
            device = (await client.post("/device_authorization", json={"client_id": "b"})).json()
            body = {"grant_type": "device_code", "device_code": device["device_code"]}
            first = await client.post("/token", data=body)
            second = await client.post("/token", data=body)

        assert first.json()["error"] == "authorization_pending"
        assert second.json()["error"] == "slow_down"
        assert second.status_code == 400

    async def test_the_ip_limit_is_the_only_one_left_for_an_unknown_code(
        self, key_pair: RSAKeyPair
    ) -> None:
        """The gap this limit is really for.

        A device code the store does not hold returns ``invalid_grant``
        BEFORE the ``slow_down`` block, so the per-code control never runs and
        never will. Each such request is a store lookup -- a Redis round trip
        under ``POSTERN_REDIS_URL``.
        """
        app = _app(key_pair)
        limit = DEFAULT_LIMITS["/token"].requests
        errors = []
        async with _client(app) as client:
            for index in range(limit + 2):
                resp = await client.post(
                    "/token",
                    data={"grant_type": "device_code", "device_code": f"nope-{index}"},
                )
                errors.append(resp.json()["error"])

        assert errors[0] == "invalid_grant"
        assert errors[limit - 1] == "invalid_grant"
        assert errors[limit] == "slow_down"

    async def test_an_approved_code_is_bounded_only_by_the_ip_limit(
        self, key_pair: RSAKeyPair
    ) -> None:
        """Named rather than implied: the per-code ``slow_down`` is skipped
        entirely once a code is approved, so for an approved code this limit
        is the only one, and at 300/min it is loose. Each poll costs an RSA
        signature and a revocation lookup."""
        app = _app(key_pair)
        async with _client(app) as client:
            device = (await client.post("/device_authorization", json={"client_id": "b"})).json()
            await client.post(
                "/approve",
                json={"device_code": device["device_code"], "user_code": device["user_code"]},
                headers=bearer(key_pair),
            )
            body = {"grant_type": "device_code", "device_code": device["device_code"]}
            statuses = [(await client.post("/token", data=body)).status_code for _ in range(20)]

        assert statuses == [200] * 20


# ---------------------------------------------------------------------------
# The limits themselves, as configured.
# ---------------------------------------------------------------------------


class TestTheConfiguredLimits:
    def test_every_public_path_carries_a_limit(self) -> None:
        for path in ("/device_authorization", "/token", "/approve", "/challenges/approve"):
            assert path in DEFAULT_LIMITS

    def test_the_token_budget_clears_rfc_8628_polling(self) -> None:
        """At the 5-second default interval one pairing polls 12 times a
        minute, so the budget must clear that by a wide margin or a browser
        with a few tabs open would trip it."""
        polls_per_minute_per_pairing = 60 // 5
        assert DEFAULT_LIMITS["/token"].requests >= polls_per_minute_per_pairing * 20

    def test_a_single_pairing_is_far_inside_the_authorization_budget(self) -> None:
        """A browser starting a pairing calls this once."""
        assert DEFAULT_LIMITS["/device_authorization"].requests >= 60

    def test_the_fallback_is_not_more_generous_than_the_named_paths(self) -> None:
        assert FALLBACK_LIMIT.requests <= max(limit.requests for limit in DEFAULT_LIMITS.values())


class TestTheLimitsAreSettableWithoutACodeChange:
    """The safety valve.

    The four defaults are keyed on a client ADDRESS BUCKET, and there is one
    deployment shape where that is badly wrong: if the operator's banking app
    BACKEND calls the two assertion-authenticated paths on the phone's behalf,
    every approval in the bank arrives from a handful of egress addresses and
    60/min becomes a bank-wide ceiling on payment approvals. Per-address is
    also the wrong unit for an authenticated path -- per customer is -- but
    fixing that needs a second limiter after ``AppAssertionMiddleware`` and is
    a different change. What these tests pin is that discovering the problem
    costs a restart rather than a release.
    """

    #: Every variable, and the field each one sets.
    NAMES = [
        ("POSTERN_CONFIRM_RATE_LIMIT_DEVICE_AUTHORIZATION", "rate_limit_device_authorization"),
        ("POSTERN_CONFIRM_RATE_LIMIT_TOKEN", "rate_limit_token"),
        ("POSTERN_CONFIRM_RATE_LIMIT_APPROVE", "rate_limit_approve"),
        ("POSTERN_CONFIRM_RATE_LIMIT_CHALLENGE_APPROVE", "rate_limit_challenge_approve"),
        ("POSTERN_CONFIRM_RATE_LIMIT_DEFAULT", "rate_limit_default"),
    ]

    @pytest.mark.parametrize(("name", "field"), NAMES)
    def test_a_value_is_read_from_the_environment(
        self, monkeypatch: pytest.MonkeyPatch, name: str, field: str
    ) -> None:
        monkeypatch.setenv(name, "1234")
        assert getattr(ConfirmSettings.from_env(), field) == 1234

    @pytest.mark.parametrize(("name", "field"), NAMES)
    @pytest.mark.parametrize("bad", ["0", "-1", "abc", "6 0", "1.5", "  "])
    def test_a_bad_value_refuses_at_startup(
        self, monkeypatch: pytest.MonkeyPatch, name: str, field: str, bad: str
    ) -> None:
        """Naming the variable, because the operator has to find it.

        Falling back to the default would be worse than never having the
        knob: the variable they set to end an outage would do nothing, and
        they would learn that from the same alert they were already reading.
        """
        monkeypatch.setenv(name, bad)
        with pytest.raises(ValueError, match=name):
            ConfirmSettings.from_env()

    @pytest.mark.parametrize(("name", "field"), NAMES)
    def test_an_unset_or_empty_variable_keeps_the_default(
        self, monkeypatch: pytest.MonkeyPatch, name: str, field: str
    ) -> None:
        monkeypatch.delenv(name, raising=False)
        unset = getattr(ConfirmSettings.from_env(), field)
        monkeypatch.setenv(name, "")
        assert getattr(ConfirmSettings.from_env(), field) == unset

    def test_the_defaults_reproduce_the_module_constants_exactly(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The override must not quietly become the source of truth.

        If these drift, an operator reading `DEFAULT_LIMITS`'s working would
        be reading about numbers the service does not run.
        """
        for name, _ in self.NAMES:
            monkeypatch.delenv(name, raising=False)
        settings = ConfirmSettings.from_env()

        assert (
            limits_from_settings(
                device_authorization=settings.rate_limit_device_authorization,
                token=settings.rate_limit_token,
                approve=settings.rate_limit_approve,
                challenge_approve=settings.rate_limit_challenge_approve,
            )
            == DEFAULT_LIMITS
        )
        assert Limit(settings.rate_limit_default, RATE_LIMIT_WINDOW_SECONDS) == FALLBACK_LIMIT

    async def test_a_raised_limit_reaches_the_assembled_app(self, key_pair: RSAKeyPair) -> None:
        """End to end: the setting an operator would reach for at 3am.

        `/challenges/{id}/approve` raised well above its default, driven
        through the real composition root.
        """
        raised = 90
        app = _app(key_pair, rate_limit_challenge_approve=raised)
        statuses = []
        async with _client(app) as client:
            for _ in range(raised + 2):
                resp = await client.post("/challenges/chal_x/approve", json={})
                statuses.append(resp.status_code)

        assert statuses[raised - 1] == 401, "still inside the raised budget"
        assert statuses[raised] == 429, "and refused one past it"
        assert raised > DEFAULT_LIMITS["/challenges/approve"].requests

    async def test_a_lowered_limit_reaches_the_assembled_app(self, key_pair: RSAKeyPair) -> None:
        app = _app(key_pair, rate_limit_device_authorization=3)
        statuses = []
        async with _client(app) as client:
            for _ in range(5):
                resp = await client.post("/device_authorization", json={"client_id": "b"})
                statuses.append(resp.status_code)

        assert statuses == [200, 200, 200, 429, 429]

    async def test_the_fallback_is_settable_too(self, key_pair: RSAKeyPair) -> None:
        app = _app(key_pair, rate_limit_default=2)
        statuses = []
        async with _client(app) as client:
            for _ in range(4):
                resp = await client.get("/.well-known/jwks.json")
                statuses.append(resp.status_code)

        assert statuses == [200, 200, 429, 429]

    @pytest.mark.parametrize("bad", [0, -1])
    def test_a_non_positive_limit_is_refused_at_construction(self, bad: int) -> None:
        """The second half of the guard, for a caller that bypasses settings.

        A limit of zero refuses every request on its path, which is an outage
        wearing a control's clothes.
        """
        with pytest.raises(ValueError, match="at least one request"):
            RateLimit(_Downstream(), limits={"/approve": Limit(bad, 60)})
        with pytest.raises(ValueError, match="at least one request"):
            RateLimit(_Downstream(), fallback_limit=Limit(bad, 60))
        with pytest.raises(ValueError, match="at least one request"):
            RateLimit(_Downstream(), pairing_limit=Limit(bad, 900))


class TestTheLimiterMemoryIsSmall:
    async def test_a_full_bucket_map_is_megabytes_not_gigabytes(self) -> None:
        """The fix must not reintroduce the defect it closes."""
        limiter = RateLimit(_Downstream(), max_buckets=2_000)
        for index in range(2_000):
            await limiter(
                _scope("/approve", peer=f"2001:db8:{index // 256:x}:{index % 256:x}::1"),
                _never_receive,
                _Sink(),
            )
        gc.collect()

        assert len(limiter._buckets) == 2_000
        per_bucket = _deep_size(limiter._buckets._buckets) / 2_000
        assert per_bucket < 1_000, f"{per_bucket} bytes per bucket"


async def test_the_expiry_heap_does_not_outgrow_the_codes_it_indexes() -> None:
    """The reaper's own index must not become the accumulator.

    Lazy deletion leaves a stale entry behind when a code is revoked, so the
    heap is bounded by codes CREATED in one lifetime rather than by codes
    alive now. What it must never do is keep growing across sweeps.
    """
    store = InMemoryDeviceCodeStore()
    for _ in range(50):
        code = await store.create_device_code(
            client_id="c", scopes="s", verification_uri="https://x.invalid/v", expires_in=1
        )
        await store.revoke_device_code(code.device_code)
    assert len(store._expiry) == 50

    await asyncio.sleep(1.1)
    await store.create_device_code(
        client_id="c", scopes="s", verification_uri="https://x.invalid/v"
    )

    # The 50 stale entries surfaced, were recognised as stale against the
    # dict, and were dropped. Only the new code's entry is left.
    assert len(store._expiry) == 1
    assert len(store._codes) == 1

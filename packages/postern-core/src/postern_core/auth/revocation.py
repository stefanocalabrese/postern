"""ZT-7 -- Revocation: three scopes, one shared store, and one decision per call.

WHAT WAS WRONG UNTIL THIS COMMIT. `RevocationList` below existed, was correct,
had 24 tests, and had NO WAY TO BE POPULATED. `services/api/main.py`'s
`create_app` constructed one, handed it to `ReadTokenMinter`, and dropped the
reference; `grep -rn "revoke_session|revoke_customer_client|kill_switch"
services stub` returned zero callers. An operator who learned a customer's
session was compromised, or that an AI vendor's client was exfiltrating, had
no mechanism to act. It was also in-process memory, per replica, lost on
restart, so even a populated one would have applied to whichever replica the
operator happened to reach.

Three revocation scopes map to the three acceptance criteria in the zero-trust
plan §4:

1. **Per-session** -- revoke one ``jti`` (one device, one client) without
   affecting the customer's other sessions.
2. **Per-customer + per-client** -- revoke all sessions for a customer-client
   pair (the "connected-app list" cut).
3. **Per-client kill switch** -- revoke every session from one client across
   all customers (the "disable one AI vendor" switch).

WHICH ``jti`` THE SESSION SCOPE MEANS. The ``jti`` of the CUSTOMER's inbound
access token, read by `services/api/middleware/revocation.py`'s
`RevocationMiddleware` from the validated token's claims. Not the internal
token's: `postern_core.auth.internal_jwt.InternalTokenMinter` generates a
fresh ``jti`` on every mint, so revoking one of those would revoke a token
that has already been spent and can never be presented again.

WHY A CLI AND NOT AN ADMIN HTTP ROUTE. `postern_core.auth.revoke_cli` is the
operator surface, and the absence of a route is a decision, not an omission.
This repository has no admin identity to authenticate. `services/confirm`'s
`AppAssertionMiddleware` verifies a CUSTOMER's banking-app assertion, so
pointing it at an admin route would mean either accepting any customer's
assertion to revoke anybody, or inventing an admin issuer, audience and role
claim -- a new authentication scheme, on the internet-facing MCP service, on
the one endpoint whose abuse either un-revokes an attacker or mass-revokes
every customer. `.importlinter`'s `api-not-confirm` contract also forbids
`services.api` from importing that middleware, so "reuse the pattern" would
mean writing a second verifier rather than reusing one. The CLI's
authorization is instead "can reach the configured Redis and run the
command", which is an infrastructure property the operator already owns and
already trusts with the risk session store. This paragraph would have been a
decision record; `dev-docs/` is gitignored and `docs/decisions/` holds stale
copies, so it lives here, in a tracked file, instead.

WHICH SCOPE REACHES WHICH SERVICE, STATED PLAINLY. `services/api` checks all
three, keyed on the customer access token it validates. `services/confirm`
cannot, and the reason is structural rather than an omission: the only token
it holds is a banking-app assertion minted by the operator's own app backend,
so it carries no AI-session ``jti``, and its ``client_id``/``azp`` name that
app rather than a vendor (`services/confirm/audit.py`'s `_client_id` records
the same fact for the audit column it fills). The one identity that service
holds is the customer. So the write path asks `is_customer_revoked` below,
which matches ANY pair naming that customer, and the coverage is:

- ``customer-client`` stops that customer's reads through that client AND
  their challenge approvals and device-grant token mints, through EVERY
  client. Deliberately wider on the write path than on the read path: it errs
  toward refusing money movement for a customer the operator has just
  declared compromised, and ``restore-customer-client`` undoes it.
- ``session`` stops reads only. The ``jti`` an operator names belongs to the
  AI client's access token, and no request on the write path carries it.
- ``kill-switch`` stops reads, and (since 3 October 2026) the device-grant
  exchange for that declared ``client_id``, but no challenge approval.
  ``challenges`` records no client id, so enforcing a kill switch there
  would mean refusing every customer's approvals rather than that client's.

**TO STOP THE WRITE PATH, NAME THE CUSTOMER.** `postern_core.auth.revoke_cli`
says the same where an operator will meet it, and
`services/confirm/revocation.py` says it at the check site.

THE EXACT KEYING IS THE RIGHT END STATE AND IS ONLY HALF BUILT. The producer
(`services/api/tools/payments.py`) records the AI session's ``client_id`` and
``session_jti`` on each challenge it creates (migration `b5d1e7a3c902`).
Matching all three scopes precisely on the approval path is still not built.

WHAT IS ALSO NOT BUILT. The zero-trust plan §4's fourth ZT-7 bullet -- the
customer cutting their own sessions from inside the bank app, and seeing
which client accessed what -- is a customer-initiated action whose home is
`services/confirm`, which already derives a customer from a verified
assertion. It is not built here. The operator's own banking-app backend can
write to this same store, and that is the documented route until a route
exists.

PERSISTENCE AND REPLICA REACH. `create_revocation_store` reads
``POSTERN_REDIS_URL`` and returns `RedisRevocationStore` when it is set,
`InMemoryRevocationStore` otherwise, following the shape
`postern_core.auth.device_codes.create_device_code_store` and
`postern_core.risk.session.create_session_store` already use. A deployment
that does not set it gets a store that is per replica and dies on restart,
which for a revocation list is worse than useless, because an operator would
believe they had acted. ``POSTERN_REQUIRE_REDIS=1`` is what a production
deployment sets to refuse startup without one;
`postern_core.config.enforce_redis_requirement` is the one implementation and
both composition roots call it. It was read in `services/api/main.py` alone
until 2026-09-26, which meant the read path refused to start and
`services/confirm` -- holding this list, the device code store and the
per-customer approval counters -- started anyway.

NO TTL. Revocation keys never expire (the stamps below are not revocations).
A kill switch that silently lapsed after thirty minutes, the way a risk
context does, would be worse than no kill switch: the operator would have
acted once and been un-acted on by a timer. Every scope has an explicit restore command instead.

ONE SET IS PRUNED, BECAUSE ITS ENTRIES DIE ON THEIR OWN. Keys (all under the
configured prefix): ``revoked:sessions`` (SET of access-token ``jti``),
``revoked:sessions:exp`` (ZSET index, member ``jti``, score the prune-after
instant in ms), ``revoked:customer-clients`` (SET), ``revoked:clients`` (SET),
``revoked:customer-at:<customer>``, ``revoked:pair-at:<pair>`` and
``revoked:client-at:<client>`` (stamps with TTLs). A ``jti`` in
``revoked:sessions`` names a layer-1 access token that is useless once it
expires, so `revoke_session` writes the SET member and the
index entry in one script and `prune_sessions` removes both after
`SESSION_REVOKED_RETENTION_SECONDS`. ``is_revoked`` still reads only the SET.
A SET member with no index entry (the operator's own backend writing a plain
``SADD``, which the paragraph above sanctions) is never pruned, and
``revoke.py prune-sessions`` prints how many exist. The other two sets hold
operator decisions, not token ids, and are never pruned.

KEYS THAT DO EXPIRE, AND THEY ARE NOT REVOCATIONS. Every customer-plus-client
revocation also stamps WHEN it was written, per customer, in milliseconds:
``customer_revoked_at``. The layer-1 session token compares that instant with
when a refresh family was created and when a device code was approved, so a
family or an approval that predates a revocation stays refused after the
revocation is restored. The stamp outlives a restore on purpose and expires
after `CUSTOMER_REVOKED_AT_TTL_SECONDS`, the longest anything it could refuse
can live, because keeping a record that a named customer was cut off beyond
that serves nothing (GDPR Article 5(1)(e)).

THE API HALF OF THE SAME RULE: ``pair-at``. The same script also stamps the
PAIR (``revoked:pair-at:<pair member>``), expiring after
`PAIR_REVOKED_AT_TTL_SECONDS` (930 s). `is_revoked` called with an ``iat`` in
its claims, as `services/api/middleware/revocation.py` does on every call,
reads that stamp in the same round trip and refuses a token whose ``iat`` is
not past it by `PAIR_IAT_TOLERANCE_MS`, so a restore no longer revives the
access tokens (up to 600 s) minted before the revocation. A missing or
non-numeric ``iat`` refuses while a stamp exists. Claims with no ``iat`` key
(`services/confirm`'s refresh check) are not floored.

THE KILL SWITCH HAS THE SAME RULE, SINCE 3 OCTOBER 2026: ``client-at``.
`kill_switch` writes ``revoked:client-at:<client_id>`` in the same script and
on the same Redis ``TIME`` as its ``SADD``, expiring after
`CLIENT_REVOKED_AT_TTL_SECONDS` (3,900 s), and `restore_client` leaves it.
`is_revoked` with an ``iat`` key floors on it exactly as on ``pair-at`` (one
more ``GET`` in the same pipeline, same tolerance, same fail-closed ``iat``),
and confirm's refresh refuses and revokes for good a family whose creation is
at or before it. A restore lets the client back in for what is issued after
the kill, which is what restoring a client means; what existed at the kill is
what the switch exists to stop.

A PER-``jti`` RESTORE IS NOT A RESIDUAL, IT IS THE VERB. `restore_session`
revives exactly the token it names, for what remains of its 600 s, and
nothing else: no stamp, no family record. A family the refresh store revoked
(reuse, recall, ``issued_before_revocation``) stays revoked there, and if the
family is presented again, its live ``jti`` values are listed again (this one
included while it lives); a family refused only because the
``jti`` was listed refreshes again, as it would once the token expired.

FAIL CLOSED. A store that cannot answer raises `RevocationStoreUnavailable`
and the middleware refuses the call. Reporting an outage as "not revoked"
would silently un-revoke every entry at exactly the moment the operator most
believes they have acted. This adds no new outage mode: the risk session
store already refuses every call on the same Redis being unreachable
(`postern_core.risk.session.SessionStoreUnavailable`).

NO CACHE. One Redis round trip per checked request. ZT-7's acceptance bar is
"terminates access within 30 seconds", and any cache TTL spends that budget
for a saving measured against a call that already makes a database write and
an HTTP request to the operator's backend.

ONE DECISION PER CALL. The check runs once, in the middleware, and its answer
is published on a `ContextVar` that `postern_core.auth.read_minter`'s
`ReadTokenMinter` reads synchronously before it signs anything. The minter
cannot do the lookup itself: it is called from
`postern_core.facade.client`'s `get_json` through a synchronous
`TokenMinter` protocol, and a Redis read is a coroutine. The alternative
considered and rejected was a second, in-process `RevocationList` held by the
minter: with Redis configured nothing would ever populate it, so the minter
would have been checking a permanently empty list -- a control that looks
like a control, which is the defect this whole commit exists to remove.

**AN UNSET DECISION REFUSES.** `require_revocation_decision` raises rather
than returning "not revoked". An unset `ContextVar` means the middleware did
not run, which cannot happen in a `create_app`-assembled server, so it is
either a future code path that bypassed the check or a directly constructed
minter. Both must refuse. A directly constructed minter that genuinely has no
revocation to consult passes `unchecked_revocation` explicitly, which is
greppable; a seam that defaulted to permissive is how a control stays inert.

Usage:
    store = create_revocation_store()
    await store.revoke_session(jti="tok-9f2")
    await store.revoke_customer_client(customer_ref="cust_7f3a", client_id="vendor-claude")
    await store.kill_switch(client_id="vendor-claude")

    claims = {"jti": "tok-9f2", "sub": "cust_7f3a", "client_id": "vendor-claude"}
    assert await store.is_revoked(claims)

See ``tests/test_zt7_revocation.py`` for the `RevocationList` matrix and
``tests/test_zt7_revocation_reachable.py`` for the end-to-end path.
"""

from __future__ import annotations

import json
import logging
import math
import os
import time
from abc import ABC, abstractmethod
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Any

from postern_core.auth.refresh_sessions import SESSION_ABSOLUTE_LIFETIME
from postern_core.auth.session_lifetime import (
    ACCESS_TOKEN_LIFETIME_SECONDS,
    SESSION_CLOCK_SKEW_SECONDS,
)
from postern_core.config import redis_url_from_env

logger = logging.getLogger(__name__)

#: The slack ``CUSTOMER_REVOKED_AT_TTL_SECONDS`` keeps beyond the longest
#: thing it must cover, for replication lag and the 2-second cross-clock
#: tolerance. ``ConfirmSettings`` subtracts the same value for its device-code
#: ceiling, so the two cannot drift apart.
REVOKED_AT_MARGIN_SECONDS = 300

#: How long ``customer_revoked_at`` remembers a customer revocation, restored
#: or not. The refresh-family lifetime (3,600 s) plus the default device-code
#: lifetime (900 s), the longest a family or an approved-but-unexchanged code
#: can outlive the revocation it must be compared with, plus
#: ``REVOKED_AT_MARGIN_SECONDS``: 4,800 s. A constant here and not a setting,
#: because the writer (`postern_core.auth.revoke_cli`, or an operator's own
#: backend) does not know confirm's settings; ``ConfirmSettings`` refuses a
#: device-code lifetime that would outgrow it.
CUSTOMER_REVOKED_AT_TTL_SECONDS = 3_600 + 900 + REVOKED_AT_MARGIN_SECONDS

#: How long ``pair-at`` remembers a customer-client revocation for the api's
#: ``iat`` floor, restored or not: access lifetime (600 s) +
#: ``SESSION_CLOCK_SKEW_SECONDS`` (30 s) + ``REVOKED_AT_MARGIN_SECONDS``
#: (300 s) = 930 s. The 30 s is there because confirm's clock, which stamps
#: ``exp``, can run ahead of the api's, so a token can still verify that much
#: longer on the api's clock. (FastMCP's `JWTVerifier` rejects ``exp <
#: time.time()`` with no leeway; `SessionTokenVerifier`'s skew only bounds how
#: far ``exp``, ``iat`` and ``nbf`` may lie in the future.) After that no
#: access token minted before the revocation can still verify, so the stamp has
#: nothing left to refuse. Far shorter than the customer's 4,800 s stamp
#: because this one guards access tokens, not refresh families.
PAIR_REVOKED_AT_TTL_SECONDS = (
    ACCESS_TOKEN_LIFETIME_SECONDS + SESSION_CLOCK_SKEW_SECONDS + REVOKED_AT_MARGIN_SECONDS
)

#: How long ``client-at`` remembers a kill switch, restored or not. It guards
#: two things: refresh families created at or before the kill (confirm refuses
#: and revokes them), which live at most `SESSION_ABSOLUTE_LIFETIME` (3,600 s)
#: on the same Redis clock, so that plus ``REVOKED_AT_MARGIN_SECONDS``; and the
#: api's ``iat`` floor, which needs `PAIR_REVOKED_AT_TTL_SECONDS` (930 s). The
#: larger of the two: 3,900 s. No device-code term, unlike the customer's
#: 4,800 s: the device-code exchange consults the kill switch only while it
#: STANDS (the set, not this stamp), so a code approved before a kill and
#: exchanged after the restore is allowed and creates a family after the
#: stamp. Nothing compares an approval with this stamp, so no approval
#: lifetime needs covering.
CLIENT_REVOKED_AT_TTL_SECONDS = max(
    int(SESSION_ABSOLUTE_LIFETIME.total_seconds()) + REVOKED_AT_MARGIN_SECONDS,
    PAIR_REVOKED_AT_TTL_SECONDS,
)

#: How long a revoked session ``jti`` stays in ``revoked:sessions`` before a
#: prune may remove it, counted from the write: access lifetime (600 s) +
#: ``SESSION_CLOCK_SKEW_SECONDS`` (30 s) + ``REVOKED_AT_MARGIN_SECONDS`` (300 s)
#: = 930 s, the same sum and the same reasoning as `PAIR_REVOKED_AT_TTL_SECONDS`.
#: Every ``jti`` written there names a layer-1 access token, which confirm
#: stamps ``exp = iat + 600`` and which the api's verifier refuses if its ``exp``
#: lies more than 630 s ahead of its own clock, and the write happens at or
#: after the mint, so ``exp <= write + 600``; the 30 s and the 300 s are slack.
#: After this long the token cannot verify, so the entry protects nothing.
#: ASSUMPTIONS, all operator-owned: (a) confirm is the only issuer the api
#: trusts (``POSTERN_JWKS_URI`` names confirm's ``/session/jwks.json``); a
#: foreign issuer's token living past about 930 s would be re-admitted by the
#: prune. (b) confirm's clock is not ahead of the api's by more than about
#: 330 s plus the mint-to-write gap. (c) Redis ``TIME`` does not step forward
#: by more than about 330 s between the write and the prune (NTP step, or a
#: failover to a replica with a fast clock).
SESSION_REVOKED_RETENTION_SECONDS = (
    ACCESS_TOKEN_LIFETIME_SECONDS + SESSION_CLOCK_SKEW_SECONDS + REVOKED_AT_MARGIN_SECONDS
)

#: How many expired entries one opportunistic prune (inside `revoke_session`)
#: and one ``prune-sessions`` run remove at most, so a revoke is never slowed
#: by a large backlog.
SESSION_PRUNE_BATCH = 1_000

#: A session revocation and its prune-after instant, as ONE server-side step on
#: ONE clock: ``TIME``, ``SADD`` into the membership SET, then ``ZADD`` into the
#: ``:exp`` index with a score that never goes DOWN (so re-asserting a ``jti``
#: cannot shorten its retention). Done by hand and not with ``ZADD GT``, which
#: needs Redis 6.2 while this module documents 5.0. KEYS: set, index. ARGV:
#: jti, retention in milliseconds.
_REVOKE_SESSION = (
    "local t = redis.call('TIME') "
    "local ms = tonumber(t[1]) * 1000 + math.floor(tonumber(t[2]) / 1000) "
    "local score = ms + tonumber(ARGV[2]) "
    "redis.call('SADD', KEYS[1], ARGV[1]) "
    "local cur = redis.call('ZSCORE', KEYS[2], ARGV[1]) "
    "if (not cur) or tonumber(cur) < score then "
    "redis.call('ZADD', KEYS[2], score, ARGV[1]) end "
    "return score"
)

#: Remove up to ARGV[1] entries whose score is at or before Redis ``TIME``,
#: from the index and from the SET, in one atomic step. Returns the count.
#: Members of the SET with no index entry are not visible to it. KEYS: set,
#: index.
_PRUNE_SESSIONS = (
    "local t = redis.call('TIME') "
    "local ms = tonumber(t[1]) * 1000 + math.floor(tonumber(t[2]) / 1000) "
    "local ids = redis.call('ZRANGEBYSCORE', KEYS[2], '-inf', ms, 'LIMIT', 0, tonumber(ARGV[1])) "
    "for _, id in ipairs(ids) do "
    "redis.call('SREM', KEYS[1], id) "
    "redis.call('ZREM', KEYS[2], id) end "
    "return #ids"
)

#: How far an access token's ``iat`` may sit past the pair stamp and still be
#: refused, in milliseconds. ``iat`` is read from the token confirm minted, on
#: confirm's clock; the stamp is Redis ``TIME`` (or this process's clock in
#: memory). Two clocks are compared, so the floor errs toward refusal by the
#: same 2 s as `services.confirm.device_auth.APPROVAL_CLOCK_TOLERANCE_MS`,
#: which is not imported because `postern_core` sits below `services`. ``iat``
#: has one-second resolution, so ``iat * 1000`` is also up to 999 ms early.
#: Cost: a token minted within about 2 s after the stamp is refused for its
#: whole life, and the customer re-pairs. The floor assumes NTP-level skew
#: between confirm's clock and Redis ``TIME``, as ``APPROVAL_CLOCK_TOLERANCE_MS``
#: does; skew beyond 2 s lets tokens minted in that window before the stamp
#: through. The 30 s in ``PAIR_REVOKED_AT_TTL_SECONDS`` is the verifier ceiling,
#: used only to size the expiry, not this tolerance. The kill switch's
#: ``client-at`` floor uses this same tolerance; the name predates it.
PAIR_IAT_TOLERANCE_MS = 2_000

#: The revocation of a customer-client pair and its timestamps, as ONE
#: server-side step on ONE clock: ``TIME``, then the pair's ``SADD``, then the
#: customer's stamp with its expiry, then the pair's own stamp (the api's
#: ``iat`` floor) with its shorter expiry. Returns the stamp in milliseconds.
#:
#: A script that reads ``TIME`` and then writes must be replicated by its
#: effects rather than by its body. Effects replication is the default from
#: Redis 5.0 and the only mode from 7.0 (the Redis scripting introduction,
#: read 1 October 2026), so the operator's Redis must be 5.0 or later. The
#: three keys must share a slot, so it must not be a cluster: measured
#: ``CROSSSLOT`` on a single-node cluster in tests/test_redis_cluster_mode.py.
#: It runs as written on the suite's ``redis:7-alpine``.
_REVOKE_CUSTOMER_CLIENT = (
    "local t = redis.call('TIME') "
    "local ms = tonumber(t[1]) * 1000 + math.floor(tonumber(t[2]) / 1000) "
    "redis.call('SADD', KEYS[1], ARGV[1]) "
    "redis.call('SET', KEYS[2], ms, 'EX', ARGV[2]) "
    "redis.call('SET', KEYS[3], ms, 'EX', ARGV[3]) "
    "return ms"
)

#: A kill switch and its stamp, as ONE server-side step on ONE clock, the same
#: shape and the same replication argument as `_REVOKE_CUSTOMER_CLIENT`:
#: ``TIME``, the client's ``SADD``, then ``client-at`` with its expiry.
#: KEYS: clients set, client stamp. ARGV: client id, TTL in seconds.
_KILL_SWITCH = (
    "local t = redis.call('TIME') "
    "local ms = tonumber(t[1]) * 1000 + math.floor(tonumber(t[2]) / 1000) "
    "redis.call('SADD', KEYS[1], ARGV[1]) "
    "redis.call('SET', KEYS[2], ms, 'EX', ARGV[2]) "
    "return ms"
)


def _iat_ms(iat: Any) -> int | None:
    """An access token's ``iat`` in milliseconds, or ``None`` if it is unusable.

    ``bool`` is excluded because ``True`` is an ``int`` to Python and an
    ``iat`` to nobody; NaN and infinity cannot be compared with a stamp.
    """
    if isinstance(iat, bool) or not isinstance(iat, int | float):
        return None
    if isinstance(iat, float) and not math.isfinite(iat):
        return None
    return int(iat) * 1000


def _below_floor(iat: Any, stamp_ms: int) -> bool:
    """Whether a token with this ``iat`` predates a ``pair-at`` or ``client-at`` stamp.

    An unusable ``iat`` counts as predating it: a stamp exists, so the token
    cannot be shown to postdate the revocation, and the check fails closed.
    """
    iat_ms = _iat_ms(iat)
    return iat_ms is None or iat_ms <= stamp_ms + PAIR_IAT_TOLERANCE_MS


def _parse_stamp(raw: Any) -> int:
    """A stored stamp as an ``int``; a corrupt one fails closed, never crashes."""
    try:
        return int(raw)
    except (TypeError, ValueError) as exc:
        raise RevocationStoreUnavailable(
            f"revocation timestamp is corrupt: {type(exc).__name__}"
        ) from exc


def _now_ms() -> int:
    """This process's clock in milliseconds, for the in-memory backend."""
    return time.time_ns() // 1_000_000


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

    Thread-safe for the common case (single-threaded ASGI app). This is the
    in-memory CORE, not the whole mechanism: `InMemoryRevocationStore` wraps
    one to satisfy `RevocationStoreBase`, and `RedisRevocationStore` is what a
    deployment with more than one replica actually runs.

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

    def restore_session(self, *, jti: str) -> None:
        """Undo `revoke_session`. Silent when the ``jti`` was never revoked.

        The three restores exist because this list has no TTL: an entry stays
        until something removes it, so something has to be able to. Idempotent
        for the reason `RevocationStoreBase` states -- an operator undoing a
        revocation under time pressure must not have to know whether a
        colleague already did.
        """
        self._session_jtis.discard(jti)

    def restore_customer_client(self, *, customer_ref: str, client_id: str) -> None:
        """Undo `revoke_customer_client`. Silent when the pair was not revoked."""
        self._customer_client.discard((customer_ref, client_id))

    def restore_client(self, *, client_id: str) -> None:
        """Undo `kill_switch`. Silent when the client was not killed."""
        self._kill_switch.discard(client_id)

    def is_revoked(self, claims: Mapping[str, Any]) -> bool:
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


class RevokedError(PermissionError):
    """This identity's access is revoked, or no revocation decision exists.

    A `PermissionError` subclass so that the refusal reads the same way as
    `services/api/server.py`'s `token_customer_resolver` refusing a caller it
    cannot name: both are "this request does not get to proceed", and both
    escape the tool dispatch as a top-level JSON-RPC error rather than a
    ``result.isError`` the model can read around.
    """


class RevocationStoreUnavailable(RuntimeError):
    """The store could not answer, so the call must be refused.

    Never collapsed into "not revoked". A backend that reported its own
    outage as an empty revocation list would un-revoke every entry it holds,
    at exactly the moment the operator most believes they have acted.
    """


@dataclass(frozen=True)
class RevocationSnapshot:
    """Everything a store currently revokes, for the CLI's ``list`` command.

    Tuples rather than sets so the CLI prints a stable order, and so a caller
    cannot mutate a store's state through the object it was handed.
    """

    sessions: tuple[str, ...] = ()
    """Revoked ``jti`` values (per-session scope)."""

    customer_clients: tuple[tuple[str, str], ...] = ()
    """Revoked ``(customer_ref, client_id)`` pairs (connected-app scope)."""

    clients: tuple[str, ...] = ()
    """Revoked ``client_id`` values (kill-switch scope)."""

    @property
    def total(self) -> int:
        """How many entries this snapshot carries, across all three scopes."""
        return len(self.sessions) + len(self.customer_clients) + len(self.clients)


class RevocationStoreBase(ABC):
    """The operator-reachable revocation surface, in whichever backend.

    Async throughout, including the in-memory backend, so a caller writes
    ``await store.is_revoked(...)`` without knowing which one it holds -- the
    same reason `postern_core.risk.session.SessionStoreBase` is async on both
    of its backends.

    Every mutator is idempotent: revoking what is already revoked, and
    restoring what is not revoked, both succeed silently. An operator acting
    on a compromised session under time pressure must not have to care
    whether a colleague already ran the same command.
    """

    @abstractmethod
    async def is_revoked(self, claims: Mapping[str, Any]) -> bool:
        """Whether these token claims are revoked under any of the three scopes.

        THE ``iat`` CONTRACT. When ``claims`` carries an ``"iat"`` KEY (the api
        passes the token's raw claim, ``None`` if absent), two stamps are
        consulted too: the pair's ``pair-at`` and the client's ``client-at``
        (the kill switch's, since 3 October 2026). A token whose ``iat`` is
        not more than `PAIR_IAT_TOLERANCE_MS` past either stamp is refused
        even though the pair or the client was restored, and an unusable
        ``iat`` is refused while either stamp exists. With no stamp the key
        changes nothing. When the key is ABSENT both floors are skipped
        entirely, which is what `services/confirm/device_auth.py`'s
        `_refresh_revoked` relies on: it asks about a family, not a token,
        and has its own ``customer-at`` and ``client-at`` comparisons.

        Raises `RevocationStoreUnavailable` when the store cannot answer.
        """

    @abstractmethod
    async def revoke_session(self, *, jti: str) -> None:
        """Revoke one session by the ``jti`` of the customer's access token."""

    @abstractmethod
    async def restore_session(self, *, jti: str) -> None:
        """Undo `revoke_session` for this ``jti``, and nothing wider.

        WHAT A RESTORE REVIVES IS THE MEANING OF THE VERB, not a residual. It
        removes this one ``jti`` from the session set, so that one access
        token is served again for what remains of its 600 s. It writes no
        stamp and touches no refresh family. A family the refresh store
        revoked (reuse, recall, ``issued_before_revocation``) stays revoked
        there, and if the family is presented again, its live ``jti`` values
        are listed again, this one included while it lives. A family
        that was only refused because this ``jti`` was listed refreshes again,
        as it would anyway once the token expired.
        """

    @abstractmethod
    async def revoke_customer_client(self, *, customer_ref: str, client_id: str) -> None:
        """Revoke every session of one customer through one OAuth client."""

    @abstractmethod
    async def restore_customer_client(self, *, customer_ref: str, client_id: str) -> None:
        """Undo `revoke_customer_client` for this pair."""

    @abstractmethod
    async def kill_switch(self, *, client_id: str) -> None:
        """Revoke every session from one OAuth client, across all customers."""

    @abstractmethod
    async def restore_client(self, *, client_id: str) -> None:
        """Undo `kill_switch` for this client, for what is issued after it.

        Leaves the ``client-at`` stamp, so an access token or a refresh
        family that existed at the kill stays refused (`client_revoked_at`).
        """

    @abstractmethod
    async def entries(self) -> RevocationSnapshot:
        """Everything currently revoked."""

    async def prune_sessions(self, *, limit: int = SESSION_PRUNE_BATCH) -> int:
        """Remove up to ``limit`` session entries past their retention; return how many.

        Only ``jti`` values that `revoke_session` indexed are ever removed. A
        member written by anything else (the operator's backend with a plain
        ``SADD``, or this module before the index existed) has no expiry on
        record and stays, as it did before pruning existed.

        CONCRETE AND ``0`` BY DEFAULT, like `customer_revoked_at`, so a test
        double that implements only the abstract methods keeps working: a store
        with no index has nothing it may prune. Raises
        `RevocationStoreUnavailable` when the store cannot answer.
        """
        return 0

    async def unindexed_session_count(self) -> int:
        """A lower bound on revoked ``jti`` values with no expiry record (never pruned).

        Exact in memory. On Redis it is ``SCARD`` minus ``ZCARD``, which
        understates if a backend ``SREM``s set members while their index
        entries remain.
        """
        return 0

    async def is_customer_revoked(self, customer_ref: str) -> bool:
        """Whether ANY revocation names this customer, whatever the client.

        THE WRITE PATH'S QUESTION, and a different one from `is_revoked`.
        `services/confirm` holds no AI-session ``jti`` and no vendor
        ``client_id`` (this module's docstring says why), so it cannot ask the
        three-scope question at all. It can ask this one, and the answer is
        the wider of the two: cutting a customer from ONE client refuses that
        customer's challenge approvals through every client. That is the
        trade recorded above -- it errs toward refusing money movement.

        Reads only the customer-plus-client scope. A kill switch is NOT
        consulted: it names a client, `challenges` records none, so honouring
        one here would refuse every customer's approvals instead of that
        client's.

        DELIBERATELY CONCRETE AND NOT ABSTRACT, the same way `close` below is,
        and for a sharper reason. Every backend that can enumerate itself can
        answer this, so a default over `entries` is complete rather than a
        stub -- and a store that cannot enumerate raises out of `entries`,
        which makes the default FAIL CLOSED with no code of its own. An
        abstract method would instead force every existing implementation to
        grow one, including `tests/test_zt7_revocation_reachable.py`'s
        `UnreachableRevocationStore`, whose whole value is that it answers
        nothing; it inherits this and refuses, unchanged.

        `RedisRevocationStore` overrides it for one round trip instead of
        three. Nothing else needs to.

        Raises `RevocationStoreUnavailable` when the store cannot answer.
        """
        snapshot = await self.entries()
        return any(customer == customer_ref for customer, _client in snapshot.customer_clients)

    async def customer_revoked_at(self, customer_ref: str) -> int | None:
        """When a revocation last named this customer, in ms since the epoch, or ``None``.

        The latest instant any ``revoke_customer_client`` for this customer
        was written, KEPT AFTER ``restore_customer_client`` and for
        `CUSTOMER_REVOKED_AT_TTL_SECONDS` only. ``POST /token`` compares it
        with a device code's approval and with a refresh family's creation,
        so a grant that predates a revocation cannot be revived by a restore.

        CONCRETE AND ``None`` BY DEFAULT, as `is_customer_revoked` is
        concrete, so a test double that implements only the abstract methods
        keeps working. Raises `RevocationStoreUnavailable` when the store
        cannot answer.
        """
        return None

    async def client_revoked_at(self, client_id: str) -> int | None:
        """When a kill switch last named this client, in ms since the epoch, or ``None``.

        Written with the kill switch, in the same step, KEPT AFTER
        ``restore_client`` and for `CLIENT_REVOKED_AT_TTL_SECONDS` only.
        ``POST /token``'s refresh compares it with a family's creation, and
        `is_revoked` with an access token's ``iat``, so neither a family nor a
        token that existed at the kill is revived by the restore.

        CONCRETE AND ``None`` BY DEFAULT, as `customer_revoked_at` is. Raises
        `RevocationStoreUnavailable` when the store cannot answer.
        """
        return None

    async def close(self) -> None:  # noqa: B027 - concrete and empty on purpose
        """Release any connection this store holds. A no-op by default.

        Deliberately NOT abstract. Only `RedisRevocationStore` holds anything
        to release, and making every backend implement an empty method is how
        a caller ends up not calling it at all. `postern_core.auth.revoke_cli`
        closes whatever store it built, without asking which one it is.
        """
        return None


class InMemoryRevocationStore(RevocationStoreBase):
    """`RevocationList` behind the async store interface.

    Per process, so under more than one replica an entry written here applies
    to whichever replica the writer reached and to no other, and a restart
    forgets it. That is a deployment property and it is why production sets
    ``POSTERN_REDIS_URL``; ``POSTERN_REQUIRE_REDIS=1`` is how an operator
    refuses to start without one, on both services since 2026-09-26 and on
    `services/api` alone before that.

    The three sets beside the list are what `entries` reads. `RevocationList`
    indexes for O(1) lookup and exposes only counts, and the CLI's ``list``
    command needs the values back; keeping them here rather than reaching into
    the lookup structure leaves that structure free to change shape.
    """

    def __init__(self, revocation_list: RevocationList | None = None) -> None:
        self._list = revocation_list or RevocationList()
        self._sessions: set[str] = set()
        self._customer_clients: set[tuple[str, str]] = set()
        self._clients: set[str] = set()
        #: ``customer_ref -> (stamp ms, expiry ms)``, swept on read.
        self._revoked_at: dict[str, tuple[int, int]] = {}
        #: ``(customer_ref, client_id) -> (stamp ms, expiry ms)``, swept on
        #: read: the api's ``iat`` floor, on the same clock as ``_revoked_at``.
        self._pair_revoked_at: dict[tuple[str, str], tuple[int, int]] = {}
        #: ``client_id -> (stamp ms, expiry ms)``, swept on read: the kill
        #: switch's stamp, for the api's ``iat`` floor and confirm's refresh.
        self._client_revoked_at: dict[str, tuple[int, int]] = {}
        #: ``jti -> prune-after instant in ms``: the twin of the ``:exp`` index.
        self._session_expiry: dict[str, int] = {}

    @staticmethod
    def _live_stamp(stamps: dict[Any, tuple[int, int]], key: Any) -> int | None:
        """The stamp under ``key`` if it has not expired; an expired one is swept."""
        entry = stamps.get(key)
        if entry is None:
            return None
        stamp, expires = entry
        if _now_ms() >= expires:
            del stamps[key]
            return None
        return stamp

    async def is_revoked(self, claims: Mapping[str, Any]) -> bool:
        """Applies the pair and client floors only when the claims carry an iat key.

        See `RevocationStoreBase.is_revoked`.
        """
        if self._list.is_revoked(claims):
            return True
        if "iat" not in claims:
            return False
        customer_ref = claims.get("sub")
        client_id = claims.get("client_id")
        if not isinstance(client_id, str):
            return False
        stamps = [self._live_stamp(self._client_revoked_at, client_id)]
        if isinstance(customer_ref, str):
            stamps.append(self._live_stamp(self._pair_revoked_at, (customer_ref, client_id)))
        return any(stamp is not None and _below_floor(claims["iat"], stamp) for stamp in stamps)

    async def revoke_session(self, *, jti: str) -> None:
        await self._revoke_session_for(jti, SESSION_REVOKED_RETENTION_SECONDS * 1000)
        try:
            await self.prune_sessions()
        except Exception:
            logger.warning("session revocation prune failed; the revoke stands", exc_info=True)

    async def _revoke_session_for(self, jti: str, retention_ms: int) -> None:
        """Revoke ``jti`` and index it to be pruned ``retention_ms`` from now.

        The index score only ever moves up. Split from `revoke_session` so a
        test can write an instant that is already past without sleeping.
        """
        self._list.revoke_session(jti=jti)
        self._sessions.add(jti)
        score = _now_ms() + retention_ms
        current = self._session_expiry.get(jti)
        if current is None or current < score:
            self._session_expiry[jti] = score

    async def restore_session(self, *, jti: str) -> None:
        self._list.restore_session(jti=jti)
        self._sessions.discard(jti)
        self._session_expiry.pop(jti, None)

    async def prune_sessions(self, *, limit: int = SESSION_PRUNE_BATCH) -> int:
        now = _now_ms()
        due = sorted((score, jti) for jti, score in self._session_expiry.items() if score <= now)[
            :limit
        ]
        for _score, jti in due:
            self._list.restore_session(jti=jti)
            self._sessions.discard(jti)
            del self._session_expiry[jti]
        return len(due)

    async def unindexed_session_count(self) -> int:
        return len(self._sessions - self._session_expiry.keys())

    async def revoke_customer_client(self, *, customer_ref: str, client_id: str) -> None:
        self._list.revoke_customer_client(customer_ref=customer_ref, client_id=client_id)
        self._customer_clients.add((customer_ref, client_id))
        stamp = _now_ms()
        self._revoked_at[customer_ref] = (stamp, stamp + CUSTOMER_REVOKED_AT_TTL_SECONDS * 1000)
        self._pair_revoked_at[(customer_ref, client_id)] = (
            stamp,
            stamp + PAIR_REVOKED_AT_TTL_SECONDS * 1000,
        )

    async def customer_revoked_at(self, customer_ref: str) -> int | None:
        return self._live_stamp(self._revoked_at, customer_ref)

    async def client_revoked_at(self, client_id: str) -> int | None:
        return self._live_stamp(self._client_revoked_at, client_id)

    async def restore_customer_client(self, *, customer_ref: str, client_id: str) -> None:
        self._list.restore_customer_client(customer_ref=customer_ref, client_id=client_id)
        self._customer_clients.discard((customer_ref, client_id))

    async def kill_switch(self, *, client_id: str) -> None:
        self._list.kill_switch(client_id=client_id)
        self._clients.add(client_id)
        stamp = _now_ms()
        self._client_revoked_at[client_id] = (
            stamp,
            stamp + CLIENT_REVOKED_AT_TTL_SECONDS * 1000,
        )

    async def restore_client(self, *, client_id: str) -> None:
        self._list.restore_client(client_id=client_id)
        self._clients.discard(client_id)

    async def entries(self) -> RevocationSnapshot:
        return RevocationSnapshot(
            sessions=tuple(sorted(self._sessions)),
            customer_clients=tuple(sorted(self._customer_clients)),
            clients=tuple(sorted(self._clients)),
        )


def _pair_member(customer_ref: str, client_id: str) -> str:
    """The stored form of a customer-client pair.

    JSON rather than ``f"{customer}|{client}"``: `client_id` is not
    trustworthy as a key fragment. fastmcp 4.0.3 fills
    ``AccessToken.client_id`` from ``client_id`` or ``azp`` or ``sub``, so a
    token carrying neither of the first two puts its raw ``sub`` there, and a
    delimiter inside either half would let one pair be written in a form that
    reads back as a different pair. A two-element JSON array cannot be
    confused with another pair whatever the halves contain.
    """
    return json.dumps([customer_ref, client_id], separators=(",", ":"))


def _pair_from_member(member: str) -> tuple[str, str]:
    """Inverse of `_pair_member`, for `RedisRevocationStore.entries`."""
    parsed = json.loads(member)
    return str(parsed[0]), str(parsed[1])


class RedisRevocationStore(RevocationStoreBase):
    """Redis-backed revocation, shared by every replica and surviving restart.

    Compatible with any Redis-compatible service: AWS ElastiCache for Redis,
    Google Memorystore for Redis, Azure Cache for Redis, or a self-hosted
    instance -- the same compatibility `postern_core.risk.session`'s
    `RedisSessionStore` already documents.

    Three SETs, one per scope, so `entries` enumerates what is revoked without
    a key scan and `is_revoked` is at most three ``SISMEMBER`` calls in one
    pipeline, which is one round trip.

    NO TTL is set on any of them. See this module's docstring: a revocation
    that expires on a timer is a revocation the operator was silently un-done
    on.

    Configuration via environment variables:

    ``POSTERN_REDIS_URL``
        Redis connection string, e.g. ``redis://localhost:6379/0`` or
        ``rediss://user:pass@host:port/0`` (TLS).

    ``POSTERN_REDIS_KEY_PREFIX``
        Key prefix for multi-tenant deployments (default ``"postern:"``).
    """

    def __init__(self, url: str | None = None, key_prefix: str | None = None) -> None:
        import redis.asyncio as redis

        self._url = url or redis_url_from_env() or "redis://localhost:6379/0"
        self._prefix = key_prefix or os.environ.get("POSTERN_REDIS_KEY_PREFIX", "postern:")
        self._redis: Any = redis.from_url(  # type: ignore[no-untyped-call]
            self._url,
            decode_responses=True,
        )

    @property
    def _sessions_key(self) -> str:
        return f"{self._prefix}revoked:sessions"

    @property
    def _sessions_exp_key(self) -> str:
        """The ZSET index: member ``jti``, score its prune-after instant in ms."""
        return f"{self._prefix}revoked:sessions:exp"

    @property
    def _pairs_key(self) -> str:
        return f"{self._prefix}revoked:customer-clients"

    @property
    def _clients_key(self) -> str:
        return f"{self._prefix}revoked:clients"

    def _revoked_at_key(self, customer_ref: str) -> str:
        return f"{self._prefix}revoked:customer-at:{customer_ref}"

    def _pair_revoked_at_key(self, customer_ref: str, client_id: str) -> str:
        return f"{self._prefix}revoked:pair-at:{_pair_member(customer_ref, client_id)}"

    def _client_revoked_at_key(self, client_id: str) -> str:
        """One component after a fixed prefix, so no delimiter can alias another client."""
        return f"{self._prefix}revoked:client-at:{client_id}"

    async def is_revoked(self, claims: Mapping[str, Any]) -> bool:
        """Check every applicable scope in one round trip.

        Only the scopes these claims could match are queried: a call carrying
        no ``jti`` asks nothing of the session set. Claims that match no scope
        at all return False without touching Redis, because no entry could
        name them.

        When the claims carry an ``"iat"`` key and name a client, one ``GET``
        of the client's ``client-at`` stamp, and one of the pair's ``pair-at``
        stamp if they also name a customer, ride in the same pipeline; see
        `RevocationStoreBase.is_revoked` for the contract.
        """
        jti = claims.get("jti")
        customer_ref = claims.get("sub")
        client_id = claims.get("client_id")

        checks: list[tuple[str, str]] = []
        if isinstance(jti, str):
            checks.append((self._sessions_key, jti))
        if isinstance(customer_ref, str) and isinstance(client_id, str):
            checks.append((self._pairs_key, _pair_member(customer_ref, client_id)))
        if isinstance(client_id, str):
            checks.append((self._clients_key, client_id))
        if not checks:
            return False

        floor_keys: list[str] = []
        if "iat" in claims and isinstance(client_id, str):
            floor_keys.append(self._client_revoked_at_key(client_id))
            if isinstance(customer_ref, str):
                floor_keys.append(self._pair_revoked_at_key(customer_ref, client_id))

        try:
            pipe = self._redis.pipeline(transaction=False)
            for key, member in checks:
                pipe.sismember(key, member)
            for key in floor_keys:
                pipe.get(key)
            results = await pipe.execute()
        except Exception as exc:
            raise RevocationStoreUnavailable(
                f"revocation list could not be read: {type(exc).__name__}"
            ) from exc
        members, stamps = results[: len(checks)], results[len(checks) :]
        if any(bool(result) for result in members):
            return True
        return any(
            _below_floor(claims["iat"], _parse_stamp(raw)) for raw in stamps if raw is not None
        )

    async def _remove(self, key: str, member: str) -> None:
        try:
            await self._redis.srem(key, member)
        except Exception as exc:
            raise RevocationStoreUnavailable(
                f"revocation entry could not be removed: {type(exc).__name__}"
            ) from exc

    async def revoke_session(self, *, jti: str) -> None:
        """The SET member and its index entry, in one script; then a bounded prune.

        The prune is best effort: its failure is logged and the revoke stands.
        """
        await self._revoke_session_for(jti, SESSION_REVOKED_RETENTION_SECONDS * 1000)
        try:
            await self.prune_sessions()
        except Exception:
            logger.warning("session revocation prune failed; the revoke stands", exc_info=True)

    async def _revoke_session_for(self, jti: str, retention_ms: int) -> None:
        """Revoke ``jti`` and index it to be pruned ``retention_ms`` after Redis ``TIME``."""
        try:
            await self._redis.eval(
                _REVOKE_SESSION, 2, self._sessions_key, self._sessions_exp_key, jti, retention_ms
            )
        except Exception as exc:
            raise RevocationStoreUnavailable(
                f"revocation entry could not be written: {type(exc).__name__}"
            ) from exc

    async def restore_session(self, *, jti: str) -> None:
        """Remove the member AND its index entry.

        A stale index entry would NOT prune a later `revoke_session` of the
        same ``jti`` early (the score only moves up, so the newer one wins).
        The cleanup matters because the operator's backend may re-add the
        ``jti`` with a plain ``SADD`` after the restore, and a stale entry
        whose score is already past would then prune that member.
        """
        try:
            pipe = self._redis.pipeline(transaction=True)
            pipe.srem(self._sessions_key, jti)
            pipe.zrem(self._sessions_exp_key, jti)
            await pipe.execute()
        except Exception as exc:
            raise RevocationStoreUnavailable(
                f"revocation entry could not be removed: {type(exc).__name__}"
            ) from exc

    async def prune_sessions(self, *, limit: int = SESSION_PRUNE_BATCH) -> int:
        try:
            removed = await self._redis.eval(
                _PRUNE_SESSIONS, 2, self._sessions_key, self._sessions_exp_key, limit
            )
        except Exception as exc:
            raise RevocationStoreUnavailable(
                f"revocation list could not be pruned: {type(exc).__name__}"
            ) from exc
        return int(removed)

    async def unindexed_session_count(self) -> int:
        try:
            pipe = self._redis.pipeline(transaction=True)
            pipe.scard(self._sessions_key)
            pipe.zcard(self._sessions_exp_key)
            members, indexed = await pipe.execute()
        except Exception as exc:
            raise RevocationStoreUnavailable(
                f"revocation list could not be counted: {type(exc).__name__}"
            ) from exc
        return max(0, int(members) - int(indexed))

    async def revoke_customer_client(self, *, customer_ref: str, client_id: str) -> None:
        """The pair's ``SADD`` and the customer's stamp, in one script on Redis's clock."""
        try:
            await self._redis.eval(
                _REVOKE_CUSTOMER_CLIENT,
                3,
                self._pairs_key,
                self._revoked_at_key(customer_ref),
                self._pair_revoked_at_key(customer_ref, client_id),
                _pair_member(customer_ref, client_id),
                CUSTOMER_REVOKED_AT_TTL_SECONDS,
                PAIR_REVOKED_AT_TTL_SECONDS,
            )
        except Exception as exc:
            raise RevocationStoreUnavailable(
                f"revocation entry could not be written: {type(exc).__name__}"
            ) from exc

    async def _get_stamp(self, key: str) -> int | None:
        """One stamp ``GET``; an outage or a corrupt value fails closed."""
        try:
            raw = await self._redis.get(key)
        except Exception as exc:
            raise RevocationStoreUnavailable(
                f"revocation timestamp could not be read: {type(exc).__name__}"
            ) from exc
        return None if raw is None else _parse_stamp(raw)

    async def customer_revoked_at(self, customer_ref: str) -> int | None:
        return await self._get_stamp(self._revoked_at_key(customer_ref))

    async def client_revoked_at(self, client_id: str) -> int | None:
        return await self._get_stamp(self._client_revoked_at_key(client_id))

    async def restore_customer_client(self, *, customer_ref: str, client_id: str) -> None:
        await self._remove(self._pairs_key, _pair_member(customer_ref, client_id))

    async def kill_switch(self, *, client_id: str) -> None:
        """The client's ``SADD`` and its ``client-at`` stamp, in one script on Redis's clock."""
        try:
            await self._redis.eval(
                _KILL_SWITCH,
                2,
                self._clients_key,
                self._client_revoked_at_key(client_id),
                client_id,
                CLIENT_REVOKED_AT_TTL_SECONDS,
            )
        except Exception as exc:
            raise RevocationStoreUnavailable(
                f"revocation entry could not be written: {type(exc).__name__}"
            ) from exc

    async def restore_client(self, *, client_id: str) -> None:
        await self._remove(self._clients_key, client_id)

    async def entries(self) -> RevocationSnapshot:
        try:
            sessions = await self._redis.smembers(self._sessions_key)
            pairs = await self._redis.smembers(self._pairs_key)
            clients = await self._redis.smembers(self._clients_key)
        except Exception as exc:
            raise RevocationStoreUnavailable(
                f"revocation list could not be enumerated: {type(exc).__name__}"
            ) from exc
        return RevocationSnapshot(
            sessions=tuple(sorted(str(value) for value in sessions)),
            customer_clients=tuple(sorted(_pair_from_member(str(value)) for value in pairs)),
            clients=tuple(sorted(str(value) for value in clients)),
        )

    async def is_customer_revoked(self, customer_ref: str) -> bool:
        """One ``SMEMBERS`` on the pairs key, where the base default costs three.

        The base implementation reads `entries`, which fetches all three sets
        to answer a question that concerns one of them. This overrides it for
        that saving alone; the semantics are identical and
        `tests/test_zt7_confirm_revocation.py` pins the two backends against
        the same matrix so they cannot drift.

        O(n) IN THE NUMBER OF REVOKED PAIRS, and that is a real property
        rather than an implementation note. A SET member cannot be matched on
        its first JSON element server-side without ``SCAN`` or Lua, so every
        pair crosses the wire. It is paid once per challenge approval and once
        per device-grant exchange -- calls that already make two database
        writes and an outbound HTTP request -- and never on a read, which is
        the path with the volume. If the revoked-pair count ever reaches a
        size where that matters, the fix is a maintained
        ``revoked:customers`` index written beside the pair, which needs
        reference counting to restore correctly and was not worth it today.
        """
        try:
            members = await self._redis.smembers(self._pairs_key)
        except Exception as exc:
            raise RevocationStoreUnavailable(
                f"revocation list could not be read: {type(exc).__name__}"
            ) from exc
        return any(_pair_from_member(str(value))[0] == customer_ref for value in members)

    async def close(self) -> None:
        await self._redis.aclose()


def create_revocation_store() -> RevocationStoreBase:
    """Create a revocation store backed by the configured backend.

    Reads ``POSTERN_REDIS_URL``: if set, returns a `RedisRevocationStore`;
    otherwise returns an `InMemoryRevocationStore`. Same contract as
    `postern_core.risk.session.create_session_store` and
    `postern_core.auth.device_codes.create_device_code_store`, so one
    environment variable configures all three and no deployment ends up with
    a shared session store beside a per-replica revocation list.
    """
    redis_url = redis_url_from_env()
    if redis_url:
        logger.info("Using Redis revocation store")
        return RedisRevocationStore(url=redis_url)
    logger.info("Using in-memory revocation store (set POSTERN_REDIS_URL for Redis)")
    return InMemoryRevocationStore()


# ---------------------------------------------------------------------------
# The per-call decision: published by the middleware, read by the minter.
# ---------------------------------------------------------------------------

#: What a `ReadTokenMinter` calls to learn whether this call is revoked.
RevocationDecision = Callable[[], bool]

_decision: ContextVar[bool | None] = ContextVar("postern_revocation_decision", default=None)


def current_decision() -> bool | None:
    """The middleware's answer for this call, or ``None`` if it did not run."""
    return _decision.get()


@contextmanager
def decision_scope(revoked: bool) -> Iterator[None]:
    """Publish a revocation decision for the duration of this block.

    RESET ON EXIT, through the token `ContextVar.set` returns, and that is not
    tidiness. A value set and left set in the task that assembles the app
    would be INHERITED by every request task spawned from that context, so one
    "not revoked" written at startup would become the standing default for
    calls whose middleware never ran -- the exact permissive fallback
    `require_revocation_decision` exists to refuse.
    """
    token = _decision.set(revoked)
    try:
        yield
    finally:
        _decision.reset(token)


def require_revocation_decision() -> bool:
    """The default decision provider: an unset decision is a refusal.

    `services/api/middleware/revocation.py`'s `RevocationMiddleware` publishes
    a decision on every tool call it admits, so in a `create_app`-assembled
    server this never raises. It fires for a code path that reached the minter
    without passing that middleware, and for a `ReadTokenMinter` constructed
    directly. Both must refuse rather than sign.
    """
    decision = _decision.get()
    if decision is None:
        raise RevokedError(
            "no revocation decision for this call: the revocation middleware "
            "did not run, so this token will not be minted"
        )
    return decision


def unchecked_revocation() -> bool:
    """A decision provider that never refuses. TEST AND STARTUP SEAM ONLY.

    Named rather than written as a bare ``lambda: False`` at each site, so
    that ``grep -rn unchecked_revocation`` lists every place the ZT-7 check is
    deliberately absent. Today that is `services/api/main.py`'s startup probe,
    which mints one token for a reference to nobody before any request exists,
    and the unit tests that construct a `ReadTokenMinter` to measure something
    else entirely: the key split, request deadlines, the minter probe.
    """
    return False

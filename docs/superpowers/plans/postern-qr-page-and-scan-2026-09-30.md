# QR Page and Scan Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the RFC 8628 device grant completable by a real phone: serve the browser a pairing page and a rotating QR keyed by a display handle, add `POST /scan` so the banking app claims a pairing with a signed rotation token, and approve at `POST /approve` by `user_code` only, through compare-and-set store writes, exactly as `dev-docs/qr-page-spec.md` specifies.

**Architecture:** The device-code store in `postern_core` gains a display handle, a per-pairing QR secret, scan fields, two secondary lookups and two compare-and-set methods (`claim_scan`, `approve_scanned`) on both backends, and loses its two whole-snapshot writers. `services/confirm` gains a pure rotation-token module, `POST /scan`, five public GET routes (page, QR image, state, script, stylesheet) with strict headers and a hotlink refusal, and a rewritten `POST /approve`. Everything stays on the write-key service, recorded in decision 0021.

**Tech Stack:** Python 3.12, Starlette routes on the existing `services/confirm` app, `segno` 1.6.6 for the SVG QR, Redis `WATCH`/`MULTI`/`SET NX EX` through `redis.asyncio`, `httpx2` ASGI tests, testcontainers Postgres and Redis already started by `tests/conftest.py`.

---

## Before you start: rules that apply to every task

1. **Work in a worktree, never on `main`.** Every commit below lands on the worktree branch. Do not push.
2. **`make ci` must exit 0 before every commit.** It needs Docker running (Postgres and Redis containers) and takes about three minutes. The last step of every task runs it.
3. **Format with `uv run ruff format packages services tests`, never `make fmt`.** `make fmt` is unscoped and rewrites the Python code fences inside the markdown design documents, this plan included.
4. **The plan file itself is scanned by `make citations`.** `tools/check_citations.py` checks every `<path>.py::<symbol>` it finds in any tracked file, and every backticked possessive of the shape "backticked `.py` path, then `'s`, then a single-backticked symbol". A citation of a symbol that does not exist yet, or that a later task deletes, fails `make ci`. So:
   - Code in this plan cites NEW symbols in docstrings and comments with double backticks (``` ``verify_token`` ```) or by name and file separately. That form is not an anchor and is never checked. Keep it that way when you paste the code.
   - `uv run pytest tests/<file>.py::<test> -q` commands are exempt, because the checker skips a node id preceded by `pytest` on the same line. Keep each such command on one line.
   - Do not add a bare `<file>.<ext>:<line>` anywhere. The baseline for every new file is zero.
5. **No em-dashes in any prose or comment you write.** The existing code uses ` -- ` in comments; do the same.
6. **Match the surrounding comment density.** The code below already carries the docstrings the codebase's voice expects. Do not add more.
7. **HTTP-status controls are ASGI or Starlette routes, never FastMCP middleware** (CLAUDE.md, version traps). **The HTTP client is `httpx2`**, never `httpx`.
8. **TDD in every task:** write the failing test, run it and see the stated failure, implement, run it and see it pass, run `make ci`, commit.

## Verified facts this plan depends on

**segno 1.6.6, checked on 30 September 2026.** From PyPI (`https://pypi.org/project/segno/`): latest release 1.6.6, 12 March 2025, BSD licence, no dependencies. From the API reference (`https://segno.readthedocs.io/en/latest/api.html`) and the serializer page (`https://segno.readthedocs.io/en/stable/serializers.html`): `segno.make_qr(content, error=None, version=None, mode=None, mask=None, encoding=None, eci=False, boost_error=True)`; `QRCode.save(out, kind=None, **kw)` where `out` is a filename or an `io.BytesIO`, and SVG output is bytes; SVG keywords `xmldecl` (default True), `svgns` (default True), `scale`, `border`, `dark`, `light`, `title`, `desc`, `svgclass`, `lineclass`, `omitsize`; `error` accepts `"L"`, `"M"`, `"Q"`, `"H"`, case-insensitive. Then measured against the installed package, without touching this repository, with `uv run --no-project --with segno==1.6.6`:
- `segno.__version__ == "1.6.6"`, and the package ships `py.typed` plus `__init__.pyi`, so `mypy --strict` needs no override.
- `inspect.signature(segno.make_qr)` and `inspect.signature(QRCode.save)` print exactly the two signatures above.
- The exact call this plan uses, `segno.make_qr(link, error="m")` then `qr.save(buffer, kind="svg", scale=6, border=4, dark="#000", light="#fff", xmldecl=False)` into an `io.BytesIO`, returns `bytes` beginning `b'<svg xmlns="http://www.w3.org/2000/svg" width="246" height="246" class="segno">'`, and a module making that call passes `mypy --strict` with no errors.
- The SVG carries no copy of the encoded text, only path data, so nothing the link contains reaches the image as markup.

**The citation checker's command exemption**, read from `tools/check_citations.py`: a node id is skipped when `pytest` appears earlier on the same line and the character before the node id is not a backtick.

**What `POST /token` writes for an unknown device code**, read from `services/confirm/device_auth.py::token_endpoint` and pinned by `tests/test_pairing_audit.py`'s `test_an_unknown_device_code_at_the_token_endpoint_writes_nothing`: nothing. This matters for the first spec discrepancy at the end of this plan.

**The rate-limit and inventory counts** this plan edits, read from `tests/test_settings_bounds.py` on 30 September 2026: `KNOWN_ENV` 65, `READ_AS_STRING` 26, `BOUNDED_NAMES` 32, the reader union 39, `names_read_by("confirm")` 49. Tasks 5, 6 and 8 move them to 66/27/32/39/50, then 73/27/39/46/57, then 72/27/38/45/56.

## File structure

Created:

| File | Responsibility |
|---|---|
| `services/confirm/qr_token.py` | The rotation token: slot arithmetic, the truncated HMAC, the token string, and the one verdict `POST /scan` acts on. Pure, no I/O. |
| `services/confirm/verify_page.py` | The five public GET routes: the pairing page, the QR image, the state endpoint, the script and the stylesheet, with their headers, the page-state table and the hotlink refusal. |
| `services/confirm/static/verify.js` | The page's only script: polls `/verify/state`, rotates the QR and the app link, backs off on 429. |
| `services/confirm/static/verify.css` | The page's only stylesheet, so `style-src 'self'` has a target. |
| `tests/device_grant_helpers.py` | Shared test steps: scan a pairing through the store, compute a rotation token, overwrite an in-memory row. Not collected by pytest. |
| `tests/test_qr_token.py` | Every property of spec section 2. |
| `tests/test_device_code_pairing_store.py` | The in-memory store's new fields, lookups and compare-and-set methods. |
| `tests/test_confirm_app_link_setting.py` | `POSTERN_DEVICE_APP_LINK_URI`, its default, its inventory row and the shared-host refusal. |
| `tests/test_scan.py` | `POST /scan`: every branch, every audit row, session swap, fail-closed withdrawal. |
| `tests/test_verify_page.py` | The five public routes: headers, states, hotlink refusal, stored-value rendering. |
| `tests/test_qr_pairing_end_to_end.py` | The whole flow over ASGI, device authorization to read token. |
| `dev-docs/decisions/0021-public-html-on-the-write-key-service.md` | Why unauthenticated HTML is served by the service that holds the write key, and what would change that. |

Modified:

| File | Responsibility of the change |
|---|---|
| `packages/postern-core/src/postern_core/auth/device_codes.py` | New fields, serialization, handle-keyed `verification_uri_complete`, secondary lookups, `ScanClaim`, `claim_scan`, `approve_scanned`, `DeviceCodeStoreContended`; removal of `update_device_code`, `approve_device_code`, `user_code_attempts`. |
| `services/confirm/device_auth.py` | `creator_ip` at creation, the rewritten `POST /approve`, the new `POST /scan`, the route list. |
| `services/confirm/audit.py` | Six new `DETAIL_*` literals, `SCAN_TOOL_NAME`, `SCAN_ROUTE`, rewritten and historical docstrings. |
| `services/confirm/auth.py` | Five new `PUBLIC_PATHS` entries, each with its reason. |
| `services/confirm/settings.py` | `device_app_link_uri` with the shared-host refusal, seven rate-limit fields, removal of `user_code_max_attempts`. |
| `services/confirm/rate_limit.py` | Six new per-address limits and their settings plumbing. |
| `services/confirm/customer_rate_limit.py` | The `/scan` per-customer limit; two comments that counted three public paths. |
| `services/confirm/main.py` | Wire the new limits and the page routes; docstring lists. |
| `packages/postern-core/src/postern_core/env_inventory.py` | Eight new rows, one removed, the row-count comment. |
| `pyproject.toml`, `uv.lock` | `segno>=1.6.6,<2`. |
| `tests/test_device_grant.py`, `tests/test_pairing_audit.py`, `tests/test_zt7_confirm_revocation.py`, `tests/test_redis_backed_stores.py`, `tests/test_confirm_auth.py`, `tests/test_confirm_rate_limit.py`, `tests/test_confirm_customer_rate_limit.py`, `tests/test_confirm_body_limit.py`, `tests/test_settings_bounds.py` | Rewritten to the new contract, as each task says. |
| `docs/user-guide/getting-started.md`, `docs/user-guide/components/confirm-service.md`, `docs/user-guide/components/session-store.md`, `dev-docs/decisions/0012-device-code-single-use.md` | The four documents the spec names as going stale. |

`CLAUDE.md` is edited in Task 13 only, and only where this work makes a statement false. The user asked for that task when approving the plan; the spec does not cover it. Task 13 also adds the new variables' rows to `docs/user-guide/getting-started.md`.

---

### Task 1: The rotation token

Spec section 2. A pure module, so it lands first and everything later imports it.

**Files:**
- Create: `services/confirm/qr_token.py` (constants `SLOT_SECONDS`, `SLOTS_BACK`, `SLOTS_FORWARD`, `MAC_BYTES`, `USER_CODE_BYTES`; enum `QrVerdict`; functions `slot_at`, `message_for`, `mac_for`, `token_for`, `verify_token`)
- Test: `tests/test_qr_token.py`

- [ ] **Step 1: Write the failing test**

Create `tests/test_qr_token.py`:

```python
"""The rotation token the pairing QR carries, checked in isolation.

``services/confirm/qr_token.py`` is pure: a secret, a pairing code and a clock
slot in, a string or a verdict out. So every property section 2 of
``dev-docs/qr-page-spec.md`` states is checked here without an app, a store or
a real clock.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets

import pytest

from services.confirm.qr_token import (
    MAC_BYTES,
    SLOT_SECONDS,
    SLOTS_BACK,
    SLOTS_FORWARD,
    USER_CODE_BYTES,
    QrVerdict,
    mac_for,
    message_for,
    slot_at,
    token_for,
    verify_token,
)

SECRET = bytes(range(32))
USER_CODE = "ABC234"
NOW = 1_000_000


def test_the_constants_are_the_specs() -> None:
    assert SLOT_SECONDS == 2
    assert SLOTS_BACK == 5
    assert SLOTS_FORWARD == 1
    assert MAC_BYTES == 16
    assert USER_CODE_BYTES == 6


@pytest.mark.parametrize(
    ("unix_time", "slot"),
    [
        (0.0, 0),
        (1.999, 0),
        (2.0, 1),
        (3.5, 1),
        (4.0, 2),
        (1_790_000_001.0, 895_000_000),
    ],
)
def test_a_slot_is_two_seconds_wide(unix_time: float, slot: int) -> None:
    assert slot_at(unix_time) == slot


def test_the_message_is_six_code_bytes_then_eight_slot_bytes() -> None:
    assert message_for(USER_CODE, 0) == b"ABC234" + bytes(8)
    assert message_for(USER_CODE, 1) == b"ABC234" + (1).to_bytes(8, "big")
    assert len(message_for(USER_CODE, 2**63 - 1)) == 14


def test_no_two_pairs_share_an_encoding() -> None:
    """Fixed width is what rules out ``("ABC234", 15)`` colliding with a
    neighbouring code and slot whose concatenated digits read the same."""
    seen = {message_for(code, slot) for code in ("ABC234", "ABC235") for slot in (1, 15, 151)}
    assert len(seen) == 6


@pytest.mark.parametrize("user_code", ["ABC23", "ABC2345", "ÄBC234", ""])
def test_a_user_code_that_is_not_six_ascii_bytes_is_refused(user_code: str) -> None:
    with pytest.raises(ValueError):
        message_for(user_code, 1)


def test_the_mac_is_truncated_hmac_sha256_in_unpadded_base64url() -> None:
    digest = hmac.new(SECRET, b"ABC234" + (7).to_bytes(8, "big"), hashlib.sha256).digest()
    expected = base64.urlsafe_b64encode(digest[:16]).rstrip(b"=").decode("ascii")
    assert mac_for(SECRET, USER_CODE, 7) == expected
    assert len(mac_for(SECRET, USER_CODE, 7)) == 22


def test_a_token_is_the_slot_a_dot_and_the_mac() -> None:
    assert token_for(SECRET, USER_CODE, 7) == f"7.{mac_for(SECRET, USER_CODE, 7)}"


@pytest.mark.parametrize("slot", [NOW - 5, NOW - 1, NOW, NOW + 1])
def test_every_slot_inside_the_window_is_valid(slot: int) -> None:
    token = token_for(SECRET, USER_CODE, slot)
    assert verify_token(SECRET, USER_CODE, token, NOW) is QrVerdict.VALID


def test_one_slot_past_the_back_edge_is_stale() -> None:
    token = token_for(SECRET, USER_CODE, NOW - 6)
    assert verify_token(SECRET, USER_CODE, token, NOW) is QrVerdict.STALE


@pytest.mark.parametrize("slot", [NOW + 2, NOW + 1_000])
def test_a_future_slot_is_invalid_and_not_stale(slot: int) -> None:
    token = token_for(SECRET, USER_CODE, slot)
    assert verify_token(SECRET, USER_CODE, token, NOW) is QrVerdict.INVALID


def test_a_tampered_mac_is_invalid() -> None:
    slot, mac = token_for(SECRET, USER_CODE, NOW).split(".")
    flipped = ("B" if mac[0] == "A" else "A") + mac[1:]
    assert verify_token(SECRET, USER_CODE, f"{slot}.{flipped}", NOW) is QrVerdict.INVALID


def test_a_mac_for_a_different_user_code_is_invalid() -> None:
    token = token_for(SECRET, "XYZ789", NOW)
    assert verify_token(SECRET, USER_CODE, token, NOW) is QrVerdict.INVALID


def test_a_mac_under_a_different_secret_is_invalid() -> None:
    token = token_for(secrets.token_bytes(32), USER_CODE, NOW)
    assert verify_token(SECRET, USER_CODE, token, NOW) is QrVerdict.INVALID


def test_an_old_slot_under_the_wrong_secret_is_invalid_not_stale() -> None:
    """``qr_stale`` is a distinct answer only for a MAC that verifies, so a
    forged token for an old slot must not reach it."""
    token = token_for(secrets.token_bytes(32), USER_CODE, NOW - 50)
    assert verify_token(SECRET, USER_CODE, token, NOW) is QrVerdict.INVALID


@pytest.mark.parametrize(
    "token",
    [
        "",
        ".",
        "7",
        "7.",
        ".AAAAAAAAAAAAAAAAAAAAAA",
        "-1.AAAAAAAAAAAAAAAAAAAAAA",
        "x.AAAAAAAAAAAAAAAAAAAAAA",
        "7.AAAA",
        "7.AAAAAAAAAAAAAAAAAAAAAA==",
        "7.AAAAAAAAAAAAAAAAAAAAA$",
        "12345678901234567890.AAAAAAAAAAAAAAAAAAAAAA",
        "７.AAAAAAAAAAAAAAAAAAAAAA",
        "7.AAAAAAAAAAAAAAAAAAAAAA.7",
    ],
)
def test_a_malformed_token_is_invalid(token: str) -> None:
    assert verify_token(SECRET, USER_CODE, token, NOW) is QrVerdict.INVALID


def test_an_empty_secret_verifies_nothing() -> None:
    """A record serialized before this change has no secret, and must be
    unscannable rather than scannable with the empty key."""
    token = token_for(b"", USER_CODE, NOW)
    assert verify_token(b"", USER_CODE, token, NOW) is QrVerdict.INVALID


def test_a_stored_user_code_of_the_wrong_shape_is_invalid_not_an_exception() -> None:
    token = token_for(SECRET, USER_CODE, NOW)
    assert verify_token(SECRET, "ABC", token, NOW) is QrVerdict.INVALID
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `uv run pytest tests/test_qr_token.py -q`
Expected: collection error, `ModuleNotFoundError: No module named 'services.confirm.qr_token'`.

- [ ] **Step 3: Write the implementation**

Create `services/confirm/qr_token.py`:

```python
"""The rotation token a pairing's QR carries, and the one check made on it.

WHAT IT IS FOR. The QR on the pairing page encodes the app link with this
token in its ``qr`` parameter, and the page replaces the image every two
seconds. ``POST /scan`` refuses a token outside a twelve-second window, so a
QR that travels anywhere slower than a camera -- a screenshot in an email, an
image on a forum, a photo passed along later -- is refused by the time it
arrives. That is the whole of what rotation buys. It does not stop a live
relay or a phishing link to the genuine page; ``dev-docs/qr-page-spec.md``
says so in its "What this does not fix" section and this module does not
pretend otherwise.

THE CONSTRUCTION. ``HMAC-SHA256(qr_secret, user_code || slot)``, truncated to
16 bytes and written as unpadded base64url. ``qr_secret`` is 32 random bytes
per pairing, generated by the device-code store and never sent anywhere, so a
token for one pairing says nothing about another. The input is fixed width --
six ASCII bytes of ``user_code`` then the slot as eight big-endian bytes -- so
no two ``(user_code, slot)`` pairs share an encoding.

THE WINDOW. Five slots back and one forward. Ten seconds back covers the
camera, the app launch, the assertion fetch and the request itself; one slot
forward covers clock skew between replicas. Anything further forward is
refused as INVALID rather than STALE, because only a verifying MAC for a slot
this server has already passed earns the distinct ``qr_stale`` answer.

A TOKEN IS REPLAYABLE INSIDE ITS WINDOW. That is harmless because the first
scan of a pairing wins (``claim_scan`` in ``postern_core.auth.device_codes``)
and any later scan by another customer is a ``scan_conflict``.

Every number here is a code constant with no setting, on purpose: the window
is a security property derived from the page's two-second poll, and an
operator knob would be a way to widen it without reading this.
"""

from __future__ import annotations

import base64
import binascii
import enum
import hashlib
import hmac
import math
import re

#: The width of one slot, matching the page's two-second poll.
SLOT_SECONDS = 2

#: How many slots before the current one still verify.
SLOTS_BACK = 5

#: How many slots after the current one still verify, for replica clock skew.
SLOTS_FORWARD = 1

#: How much of the HMAC-SHA256 output the token carries.
MAC_BYTES = 16

#: The stored pairing code's width in bytes. Every stored code is six
#: characters from ``23456789ABCDEFGHJKLMNPQRSTUVWXYZ``.
USER_CODE_BYTES = 6

#: The slot as it may appear in a token: ASCII digits only, at most 19 of them
#: so the value always fits the eight bytes the MAC input reserves for it.
_SLOT_TEXT = re.compile(r"[0-9]{1,19}")

#: The MAC as it may appear: exactly the unpadded base64url of 16 bytes.
_MAC_TEXT = re.compile(r"[A-Za-z0-9_-]{22}")


class QrVerdict(enum.Enum):
    """What ``verify_token`` concluded about a presented token."""

    #: A genuine MAC for a slot inside the window.
    VALID = "valid"
    #: A genuine MAC for a slot older than the window. The trace of a relay.
    STALE = "stale"
    #: Anything else: malformed, forged, for another pairing, or from the future.
    INVALID = "invalid"


def slot_at(unix_time: float) -> int:
    """The slot a POSIX instant falls in."""
    return math.floor(unix_time / SLOT_SECONDS)


def message_for(user_code: str, slot: int) -> bytes:
    """The fixed-width MAC input. Raises ``ValueError`` for a malformed code."""
    encoded = user_code.encode("ascii")
    if len(encoded) != USER_CODE_BYTES:
        raise ValueError(f"a pairing code is {USER_CODE_BYTES} ASCII bytes, got {len(encoded)}")
    return encoded + slot.to_bytes(8, "big")


def _digest(qr_secret: bytes, user_code: str, slot: int) -> bytes:
    return hmac.new(qr_secret, message_for(user_code, slot), hashlib.sha256).digest()[:MAC_BYTES]


def mac_for(qr_secret: bytes, user_code: str, slot: int) -> str:
    """The truncated MAC, as unpadded base64url."""
    encoded = base64.urlsafe_b64encode(_digest(qr_secret, user_code, slot))
    return encoded.rstrip(b"=").decode("ascii")


def token_for(qr_secret: bytes, user_code: str, slot: int) -> str:
    """The token the QR carries for ``slot``: ``<slot>.<mac>``."""
    return f"{slot}.{mac_for(qr_secret, user_code, slot)}"


def verify_token(qr_secret: bytes, user_code: str, token: str, now_slot: int) -> QrVerdict:
    """Check a presented token against a stored pairing.

    Never raises on caller input: every malformed shape is ``INVALID``. An
    empty ``qr_secret`` -- a record written before this module existed --
    verifies nothing, so such a pairing is unscannable rather than scannable
    with the empty key.
    """
    if not qr_secret:
        return QrVerdict.INVALID
    slot_text, dot, mac_text = token.partition(".")
    if not dot or not _SLOT_TEXT.fullmatch(slot_text) or not _MAC_TEXT.fullmatch(mac_text):
        return QrVerdict.INVALID
    slot = int(slot_text)
    if slot > now_slot + SLOTS_FORWARD:
        return QrVerdict.INVALID
    try:
        presented = base64.urlsafe_b64decode(mac_text + "==")
        expected = _digest(qr_secret, user_code, slot)
    except (binascii.Error, ValueError):
        return QrVerdict.INVALID
    if not hmac.compare_digest(presented, expected):
        return QrVerdict.INVALID
    if slot < now_slot - SLOTS_BACK:
        return QrVerdict.STALE
    return QrVerdict.VALID
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `uv run pytest tests/test_qr_token.py -q`
Expected: every test passes.

- [ ] **Step 5: Format, then run the gate**

Run: `uv run ruff format packages services tests && make ci`
Expected: exit 0.

- [ ] **Step 6: Commit**

```bash
git add services/confirm/qr_token.py tests/test_qr_token.py
git commit -m "feat(confirm): add the QR rotation token" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 2: A device code carries a display handle, a QR secret and scan fields

Spec section 1, the field table and old-record compatibility. Additive: `user_code_attempts`, `update_device_code` and `approve_device_code` stay until Task 8, which is where their last callers go.

**Files:**
- Modify: `packages/postern-core/src/postern_core/auth/device_codes.py` (imports; `DeviceCode` fields and docstring; `DeviceCodeStoreBase.create_device_code`, `InMemoryDeviceCodeStore.create_device_code`, `RedisDeviceCodeStore.create_device_code`; new `DISPLAY_HANDLE_BYTES`, `QR_SECRET_BYTES`, `_generate_display_handle`, `_generate_qr_secret`; `_device_code_to_dict`, `_device_code_from_dict`)
- Create: `tests/test_device_code_pairing_store.py`
- Modify: `tests/test_redis_backed_stores.py` (one new test after `test_a_code_the_server_never_held_cannot_be_claimed`)

- [ ] **Step 1: Write the failing in-memory tests**

Create `tests/test_device_code_pairing_store.py`:

```python
"""The device-code store's pairing half, on the in-memory backend.

The fields the QR page and ``POST /scan`` read, the two secondary lookups, and
the two compare-and-set writes that replaced ``update_device_code``. The Redis
backend's versions of the same properties are in
``tests/test_redis_backed_stores.py``, against the real container ``make ci``
already starts, because the two backends share a contract and no code.
"""

from __future__ import annotations

import base64
import re
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from postern_core.auth.device_codes import DeviceCode, InMemoryDeviceCodeStore

from services.confirm.qr_token import QrVerdict, token_for, verify_token

VERIFY_URI = "https://auth.test.invalid/verify"
URLSAFE = re.compile(r"[A-Za-z0-9_-]+")


async def _create(store: InMemoryDeviceCodeStore, **kwargs: Any) -> DeviceCode:
    return await store.create_device_code(
        client_id="vendor-a", scopes="accounts:read", verification_uri=VERIFY_URI, **kwargs
    )


def _bare(**overrides: Any) -> DeviceCode:
    fields: dict[str, Any] = {
        "device_code": "dc-bare",
        "user_code": "ABC234",
        "verification_uri": VERIFY_URI,
        "expires_at": datetime.now(UTC) + timedelta(minutes=15),
    }
    fields.update(overrides)
    return DeviceCode(**fields)


# ---------------------------------------------------------------------------
# The new fields.
# ---------------------------------------------------------------------------


class TestTheNewFields:
    async def test_a_new_code_carries_a_handle_a_secret_and_its_creator(self) -> None:
        code = await _create(InMemoryDeviceCodeStore(), creator_ip="203.0.113.9")

        assert len(code.display_handle) == 22
        assert URLSAFE.fullmatch(code.display_handle)
        assert len(code.qr_secret) == 32
        assert code.creator_ip == "203.0.113.9"
        assert code.scanned_by == ""
        assert code.scanned_at is None

    async def test_creator_ip_is_none_when_the_caller_names_none(self) -> None:
        code = await _create(InMemoryDeviceCodeStore())
        assert code.creator_ip is None

    async def test_no_two_codes_share_a_handle_or_a_secret(self) -> None:
        store = InMemoryDeviceCodeStore()
        codes = [await _create(store) for _ in range(50)]

        assert len({c.display_handle for c in codes}) == 50
        assert len({c.qr_secret for c in codes}) == 50

    async def test_the_handle_is_neither_credential(self) -> None:
        code = await _create(InMemoryDeviceCodeStore())
        assert code.display_handle not in (code.device_code, code.user_code)

    def test_the_secret_stays_out_of_repr(self) -> None:
        secret = bytes(range(32))
        code = _bare(qr_secret=secret)

        assert "qr_secret" not in repr(code)
        assert repr(secret) not in repr(code)


# ---------------------------------------------------------------------------
# Serialization, and the record the previous release wrote.
# ---------------------------------------------------------------------------


class TestSerialization:
    def _full(self) -> DeviceCode:
        return _bare(
            display_handle="h" * 22,
            qr_secret=bytes(range(32)),
            creator_ip="2001:db8::7",
            scanned_by="cust_7f3a",
            scanned_at=datetime.now(UTC),
        )

    def test_every_pairing_field_round_trips_through_json(self) -> None:
        code = self._full()
        back = DeviceCode.from_json(code.to_json())

        assert back.display_handle == code.display_handle
        assert back.qr_secret == code.qr_secret
        assert back.creator_ip == "2001:db8::7"
        assert back.scanned_by == "cust_7f3a"
        assert back.scanned_at is not None and code.scanned_at is not None
        assert abs((back.scanned_at - code.scanned_at).total_seconds()) < 0.001

    def test_the_secret_is_standard_base64_in_the_serialized_form(self) -> None:
        serialized = self._full().to_dict()
        assert serialized["qr_secret"] == base64.b64encode(bytes(range(32))).decode("ascii")

    def test_an_unscanned_code_serializes_its_absences_as_absences(self) -> None:
        serialized = _bare().to_dict()

        assert serialized["qr_secret"] is None
        assert serialized["display_handle"] == ""
        assert serialized["creator_ip"] is None
        assert serialized["scanned_by"] == ""
        assert serialized["scanned_at"] is None
        assert DeviceCode.from_dict(serialized).qr_secret == b""

    def test_a_secret_that_is_not_base64_is_a_corrupt_record(self) -> None:
        serialized = self._full().to_dict()
        serialized["qr_secret"] = "not base64 at all!"  # noqa: S105
        with pytest.raises(ValueError):
            DeviceCode.from_dict(serialized)

    def test_a_record_from_the_previous_release_deserializes_unscannable(self) -> None:
        """No handle, so no page finds it; no secret, so no token verifies."""
        legacy: dict[str, Any] = {
            "device_code": "legacy",
            "user_code": "ABC234",
            "verification_uri": VERIFY_URI,
            "expires_at": (datetime.now(UTC) + timedelta(minutes=15)).timestamp(),
            "interval": 5,
            "client_id": "legacy-client",
            "scopes": "accounts:read",
            "approved": False,
            "approved_at": None,
            "customer_ref": "",
            "exchanged_at": None,
            # No display_handle, qr_secret, creator_ip, scanned_by, scanned_at.
        }
        code = DeviceCode.from_dict(legacy)

        assert code.display_handle == ""
        assert code.qr_secret == b""
        assert code.creator_ip is None
        assert code.scanned_by == ""
        assert code.scanned_at is None
        forged = token_for(code.qr_secret, code.user_code, 5)
        assert verify_token(code.qr_secret, code.user_code, forged, 5) is QrVerdict.INVALID
```

- [ ] **Step 2: Write the failing Redis test**

In `tests/test_redis_backed_stores.py`, insert this block directly after the body of `test_a_code_the_server_never_held_cannot_be_claimed` (after its last line, `assert await store._redis.exists(store._key("never-existed")) == 0`, and before the `# The session store: the two clocks, and a TTL the server enforces.` banner). Tasks 3 and 4 append more tests to the end of this block.

```python


# ---------------------------------------------------------------------------
# The pairing half: handle, secret, secondary keys, and the two compare-and-set
# writes. `tests/test_device_code_pairing_store.py` holds the in-memory side.
# ---------------------------------------------------------------------------


async def test_the_pairing_fields_cross_to_a_second_connection(stores: RedisStores) -> None:
    """The QR secret is bytes in the process and base64 on the wire, and a
    second replica must read back the same 32 bytes or no token it verifies
    will match the image the first replica drew."""
    writer = stores.device_codes()
    reader = stores.device_codes()
    code = await _create(writer, creator_ip="203.0.113.9")

    seen = await reader.get_device_code(code.device_code)

    assert seen is not None
    assert seen.display_handle == code.display_handle
    assert len(seen.display_handle) == 22
    assert seen.qr_secret == code.qr_secret
    assert len(seen.qr_secret) == 32
    assert seen.creator_ip == "203.0.113.9"
    assert seen.scanned_by == ""
    assert seen.scanned_at is None
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `uv run pytest tests/test_device_code_pairing_store.py -q`
Expected: FAIL. `TestTheNewFields` fails with `TypeError: ... create_device_code() got an unexpected keyword argument 'creator_ip'` or `AttributeError: 'DeviceCode' object has no attribute 'display_handle'`; `TestSerialization` fails with `TypeError: DeviceCode.__init__() got an unexpected keyword argument 'display_handle'`.

Run: `uv run pytest tests/test_redis_backed_stores.py::test_the_pairing_fields_cross_to_a_second_connection -q`
Expected: FAIL with `TypeError: ... unexpected keyword argument 'creator_ip'`.

- [ ] **Step 4: Implement, in `packages/postern-core/src/postern_core/auth/device_codes.py`**

4a. Imports. Replace

```python
import dataclasses
import heapq
import json as _json
import os
import secrets
from abc import ABC, abstractmethod
from dataclasses import dataclass
```

with

```python
import base64
import dataclasses
import heapq
import json as _json
import os
import secrets
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
```

4b. The `DeviceCode` docstring. Directly after the `exchanged_at:` attribute entry (the four lines ending `sits behind, and never cleared.`), add:

```python
        display_handle: 128 random bits, base64url. Keys the browser's
            pairing page, its QR image and its state endpoint, and is useless
            at ``POST /token``. Empty on a record written before it existed,
            which no page can then find.
        qr_secret: 32 random bytes, the per-pairing HMAC key for the QR's
            rotation token (``services/confirm/qr_token.py``). Never leaves
            the store and never appears in ``repr``. Empty on an older
            record, which is therefore unscannable -- the safe direction.
        creator_ip: The address ``POST /device_authorization`` came from.
            Recorded for the creator-versus-scanner comparison a later spec
            owns; nothing reads it yet.
        scanned_by: The customer whose app scanned first, from a verified
            assertion ``sub`` at ``POST /scan``. Empty until scanned.
        scanned_at: When that scan was claimed.
```

4c. The `DeviceCode` fields. Replace

```python
    user_code_attempts: int = 0
    exchanged_at: datetime | None = None
```

with

```python
    user_code_attempts: int = 0
    exchanged_at: datetime | None = None
    display_handle: str = ""
    qr_secret: bytes = field(default=b"", repr=False)
    creator_ip: str | None = None
    scanned_by: str = ""
    scanned_at: datetime | None = None
```

4d. `DeviceCodeStoreBase.create_device_code`. Replace

```python
        expires_in: int = 900,
        interval: int = 5,
    ) -> DeviceCode:
        """Create a new device code session and return it.

        Every backend must first drop what has expired and then refuse with
```

with

```python
        expires_in: int = 900,
        interval: int = 5,
        creator_ip: str | None = None,
    ) -> DeviceCode:
        """Create a new device code session and return it.

        The code carries a fresh ``display_handle`` and ``qr_secret`` and the
        ``creator_ip`` it was given, and is unscanned.

        Every backend must first drop what has expired and then refuse with
```

4e. The generators. Directly after `_generate_user_code` (after its line `return "".join(secrets.choice(alphabet) for _ in range(6))`), add:

```python


#: Random bytes behind a display handle: 128 bits, 22 base64url characters.
DISPLAY_HANDLE_BYTES = 16

#: Random bytes in a pairing's QR secret, the HMAC-SHA256 key of its rotation
#: token. 32 is SHA-256's output size; RFC 2104 section 3 discourages a key
#: shorter than that.
QR_SECRET_BYTES = 32


def _generate_display_handle() -> str:
    """Generate the value that keys the browser's pairing page."""
    return secrets.token_urlsafe(DISPLAY_HANDLE_BYTES)


def _generate_qr_secret() -> bytes:
    """Generate a pairing's rotation-token key."""
    return secrets.token_bytes(QR_SECRET_BYTES)
```

4f. `InMemoryDeviceCodeStore.create_device_code`: add `creator_ip: str | None = None,` as the last keyword parameter, after `interval: int = 5,`. In the same method replace

```python
            client_id=client_id,
            scopes=scopes,
        )
        self._codes[device_code] = code
```

with

```python
            client_id=client_id,
            scopes=scopes,
            display_handle=_generate_display_handle(),
            qr_secret=_generate_qr_secret(),
            creator_ip=creator_ip,
        )
        self._codes[device_code] = code
```

4g. `RedisDeviceCodeStore.create_device_code`: add `creator_ip: str | None = None,` after `interval: int = 5,`. In the same method replace

```python
            client_id=client_id,
            scopes=scopes,
        )
        await self._set_code(device_code, code)
        return code
```

with

```python
            client_id=client_id,
            scopes=scopes,
            display_handle=_generate_display_handle(),
            qr_secret=_generate_qr_secret(),
            creator_ip=creator_ip,
        )
        await self._set_code(device_code, code)
        return code
```

4h. `_device_code_to_dict`. Replace

```python
        "exchanged_at": dc.exchanged_at.timestamp() if dc.exchanged_at else None,
    }
```

with

```python
        "exchanged_at": dc.exchanged_at.timestamp() if dc.exchanged_at else None,
        "display_handle": dc.display_handle,
        # Standard base64 so the JSON stays text. ``None`` rather than ``""``
        # for an absent secret, so a reader of the stored value can tell "no
        # secret" from a secret that happens to encode short.
        "qr_secret": base64.b64encode(dc.qr_secret).decode("ascii") if dc.qr_secret else None,
        "creator_ip": dc.creator_ip,
        "scanned_by": dc.scanned_by,
        "scanned_at": dc.scanned_at.timestamp() if dc.scanned_at else None,
    }
```

4i. `_device_code_from_dict`. Replace

```python
    exchanged_at = None
    if data.get("exchanged_at") is not None:
        exchanged_at = datetime.fromtimestamp(data["exchanged_at"], tz=_UTC)
    return DeviceCode(
```

with

```python
    exchanged_at = None
    if data.get("exchanged_at") is not None:
        exchanged_at = datetime.fromtimestamp(data["exchanged_at"], tz=_UTC)
    scanned_at = None
    if data.get("scanned_at") is not None:
        scanned_at = datetime.fromtimestamp(data["scanned_at"], tz=_UTC)
    # ``validate=True`` so a stored value that is not base64 raises
    # ``binascii.Error``, a ``ValueError``, which every caller already treats
    # as a corrupt record, rather than decoding to a different key.
    raw_secret = data.get("qr_secret")
    qr_secret = base64.b64decode(raw_secret, validate=True) if raw_secret else b""
    raw_creator_ip = data.get("creator_ip")
    return DeviceCode(
```

and at the end of the same `return DeviceCode(...)` call replace

```python
        exchanged_at=exchanged_at,
    )
```

with

```python
        exchanged_at=exchanged_at,
        # ALL FIVE DEFAULT TO ABSENT, and for the pairing that is the
        # fail-closed direction: a record the previous release wrote has no
        # handle, so no page finds it, and no secret, so no rotation token
        # verifies against it. It cannot be scanned and so cannot be approved;
        # with a 900-second lifetime none outlives a deploy by long.
        display_handle=str(data.get("display_handle", "")),
        qr_secret=qr_secret,
        creator_ip=str(raw_creator_ip) if raw_creator_ip is not None else None,
        scanned_by=str(data.get("scanned_by", "")),
        scanned_at=scanned_at,
    )
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `uv run pytest tests/test_device_code_pairing_store.py tests/test_device_grant.py -q`
Expected: all pass.

Run: `uv run pytest tests/test_redis_backed_stores.py -q`
Expected: all pass.

- [ ] **Step 6: Format, then run the gate**

Run: `uv run ruff format packages services tests && make ci`
Expected: exit 0.

- [ ] **Step 7: Commit**

```bash
git add packages/postern-core/src/postern_core/auth/device_codes.py tests/test_device_code_pairing_store.py tests/test_redis_backed_stores.py
git commit -m "feat(core): give a device code a display handle, a QR secret and scan fields" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 3: Look a device code up by display handle and by user code

Spec section 1, first bullet of "New store methods": secondary keys created with `SET NX EX` (a collision regenerates, check-then-set is never used), deleted on revoke only, left in place by consume, and a lookup that re-reads and re-checks the primary. In memory, two dicts that `_drop_expired` and `revoke_device_code` also clear.

**Files:**
- Modify: `packages/postern-core/src/postern_core/auth/device_codes.py` (new `DeviceCodeStoreContended`, `_SECONDARY_KEY_ATTEMPTS`, `_live_match`, `_unused`; abstract `get_by_display_handle`, `get_by_user_code`; `InMemoryDeviceCodeStore.__init__`, new `_forget`, `_drop_expired`, `create_device_code`, new lookups, `revoke_device_code`; `RedisDeviceCodeStore` new `_handle_key`, `_user_code_key`, `_secondary_keys`, `_claim_secondary`, `create_device_code`, new lookups, `revoke_device_code`)
- Test: `tests/test_device_code_pairing_store.py` (import block, new class `TestTheSecondaryLookups`)
- Test: `tests/test_redis_backed_stores.py` (import block, eight new tests)

- [ ] **Step 1: Write the failing in-memory tests**

In `tests/test_device_code_pairing_store.py`, replace the import block

```python
import base64
import re
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from postern_core.auth.device_codes import DeviceCode, InMemoryDeviceCodeStore
```

with

```python
import base64
import re
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from postern_core.auth import device_codes
from postern_core.auth.device_codes import (
    DeviceCode,
    DeviceCodeStoreContended,
    InMemoryDeviceCodeStore,
)
```

and append at the end of the file:

```python


# ---------------------------------------------------------------------------
# The two secondary lookups.
# ---------------------------------------------------------------------------


class TestTheSecondaryLookups:
    async def test_both_lookups_find_the_code(self) -> None:
        store = InMemoryDeviceCodeStore()
        code = await _create(store)

        assert await store.get_by_display_handle(code.display_handle) == code
        assert await store.get_by_user_code(code.user_code) == code

    async def test_an_unknown_or_empty_value_finds_nothing(self) -> None:
        store = InMemoryDeviceCodeStore()
        await _create(store)

        assert await store.get_by_display_handle("no-such-handle") is None
        assert await store.get_by_display_handle("") is None
        assert await store.get_by_user_code("") is None

    async def test_an_expired_code_is_found_by_neither(self) -> None:
        """Unlike ``get_device_code``, which must still return it so that
        ``POST /token`` can answer RFC 8628's ``expired_token``."""
        store = InMemoryDeviceCodeStore()
        code = await _create(store)
        past = datetime.now(UTC) - timedelta(seconds=1)
        store._codes[code.device_code] = replace(code, expires_at=past)

        assert await store.get_by_display_handle(code.display_handle) is None
        assert await store.get_by_user_code(code.user_code) is None
        assert await store.get_device_code(code.device_code) is not None

    async def test_an_entry_pointing_at_another_code_is_not_trusted(self) -> None:
        store = InMemoryDeviceCodeStore()
        first = await _create(store)
        second = await _create(store)
        store._by_user_code[first.user_code] = second.device_code
        store._by_handle[first.display_handle] = second.device_code

        assert await store.get_by_user_code(first.user_code) is None
        assert await store.get_by_display_handle(first.display_handle) is None

    async def test_a_revoke_clears_both_entries(self) -> None:
        store = InMemoryDeviceCodeStore()
        code = await _create(store)

        await store.revoke_device_code(code.device_code)

        assert code.user_code not in store._by_user_code
        assert code.display_handle not in store._by_handle
        assert await store.get_by_user_code(code.user_code) is None

    async def test_a_consumed_code_still_resolves_by_both(self) -> None:
        """``POST /scan`` must still find an exchanged row, to answer
        ``conflict_exchanged`` rather than ``gone``."""
        store = InMemoryDeviceCodeStore()
        code = await _create(store)

        assert await store.consume_device_code(code.device_code) is True

        by_code = await store.get_by_user_code(code.user_code)
        assert by_code is not None and by_code.exchanged_at is not None
        assert await store.get_by_display_handle(code.display_handle) is not None

    async def test_the_expiry_sweep_clears_both_entries(self) -> None:
        store = InMemoryDeviceCodeStore()
        due = await _create(store, expires_in=0)

        await _create(store)

        assert due.device_code not in store._codes
        assert due.user_code not in store._by_user_code
        assert due.display_handle not in store._by_handle

    async def test_a_colliding_user_code_is_regenerated(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        store = InMemoryDeviceCodeStore()
        first = await _create(store)
        spellings = iter([first.user_code, "XYZ789"])
        monkeypatch.setattr(device_codes, "_generate_user_code", lambda: next(spellings))

        second = await _create(store)

        assert second.user_code == "XYZ789"
        assert await store.get_by_user_code(first.user_code) == first

    async def test_a_colliding_handle_is_regenerated(self, monkeypatch: pytest.MonkeyPatch) -> None:
        store = InMemoryDeviceCodeStore()
        first = await _create(store)
        spellings = iter([first.display_handle, "fresh-handle-0000000000"])
        monkeypatch.setattr(device_codes, "_generate_display_handle", lambda: next(spellings))

        second = await _create(store)

        assert second.display_handle == "fresh-handle-0000000000"
        assert await store.get_by_display_handle(first.display_handle) == first

    async def test_a_generator_that_only_collides_is_refused_not_looped(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        store = InMemoryDeviceCodeStore()
        first = await _create(store)
        monkeypatch.setattr(device_codes, "_generate_user_code", lambda: first.user_code)

        with pytest.raises(DeviceCodeStoreContended):
            await _create(store)
```

- [ ] **Step 2: Write the failing Redis tests**

In `tests/test_redis_backed_stores.py`, replace

```python
import redis.exceptions
from postern_core.auth.device_codes import (
    MIN_DEVICE_CODE_TTL_SECONDS,
    DeviceCode,
    DeviceCodeStoreFull,
```

with

```python
import redis.exceptions
from postern_core.auth import device_codes
from postern_core.auth.device_codes import (
    MIN_DEVICE_CODE_TTL_SECONDS,
    DeviceCode,
    DeviceCodeStoreContended,
    DeviceCodeStoreFull,
```

and append after `test_the_pairing_fields_cross_to_a_second_connection` (Task 2's test, the last one in the pairing block):

```python


async def test_both_secondary_lookups_resolve_on_a_second_connection(
    stores: RedisStores,
) -> None:
    writer = stores.device_codes()
    reader = stores.device_codes()
    code = await _create(writer)

    assert await reader.get_by_display_handle(code.display_handle) == code
    assert await reader.get_by_user_code(code.user_code) == code
    assert await reader.get_by_user_code("") is None
    assert await reader.get_by_display_handle("") is None


async def test_the_secondary_keys_carry_the_codes_lifetime(stores: RedisStores) -> None:
    """``SET NX EX`` in one command, so a secondary key without a TTL cannot
    exist even if the connection drops mid-create."""
    store = stores.device_codes()
    code = await _create(store, expires_in=120)

    for key in (store._user_code_key(code.user_code), store._handle_key(code.display_handle)):
        assert 118 <= await store._redis.ttl(key) <= 120, key
        assert await store._redis.get(key) == code.device_code


async def test_a_secondary_key_naming_another_code_is_not_trusted(stores: RedisStores) -> None:
    store = stores.device_codes()
    code = await _create(store)
    await store._redis.set(store._user_code_key("ZZZ999"), code.device_code, ex=60)
    await store._redis.set(store._handle_key("forged-handle"), code.device_code, ex=60)

    assert await store.get_by_user_code("ZZZ999") is None
    assert await store.get_by_display_handle("forged-handle") is None


async def test_an_expired_primary_is_not_found_through_a_secondary_key(
    stores: RedisStores,
) -> None:
    """The secondary key can outlive the primary's own ``expires_at`` by up to
    a second under ``_set_code``'s truncation, so the lookup re-checks it."""
    store = stores.device_codes()
    code = await _create(store)
    stale = dataclasses.replace(code, expires_at=datetime.now(UTC) - timedelta(seconds=1))
    await store._redis.set(store._key(code.device_code), stale.to_json(), keepttl=True)

    assert await store.get_by_user_code(code.user_code) is None
    assert await store.get_by_display_handle(code.display_handle) is None


async def test_a_revoke_deletes_both_secondary_keys(stores: RedisStores) -> None:
    store = stores.device_codes()
    code = await _create(store)

    await store.revoke_device_code(code.device_code)

    assert await store._redis.exists(store._user_code_key(code.user_code)) == 0
    assert await store._redis.exists(store._handle_key(code.display_handle)) == 0


async def test_a_consumed_code_still_resolves_by_both_keys(stores: RedisStores) -> None:
    store = stores.device_codes()
    code = await _create(store)

    assert await store.consume_device_code(code.device_code) is True

    found = await store.get_by_user_code(code.user_code)
    assert found is not None and found.exchanged_at is not None
    assert await store.get_by_display_handle(code.display_handle) is not None


async def test_a_taken_user_code_key_is_regenerated_not_overwritten(
    stores: RedisStores, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = stores.device_codes()
    await store._redis.set(store._user_code_key("ABC234"), "someone-else", ex=600)
    spellings = iter(["ABC234", "DEF567"])
    monkeypatch.setattr(device_codes, "_generate_user_code", lambda: next(spellings))

    code = await _create(store)

    assert code.user_code == "DEF567"
    assert await store._redis.get(store._user_code_key("ABC234")) == "someone-else"
    assert await store._redis.get(store._user_code_key("DEF567")) == code.device_code


async def test_a_generator_that_only_collides_raises_rather_than_looping(
    stores: RedisStores, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = stores.device_codes()
    await store._redis.set(store._user_code_key("ABC234"), "someone-else", ex=600)
    monkeypatch.setattr(device_codes, "_generate_user_code", lambda: "ABC234")

    with pytest.raises(DeviceCodeStoreContended):
        await _create(store)
    assert await store._redis.zcard(store._index_key()) == 0, "nothing half-created was indexed"
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `uv run pytest tests/test_device_code_pairing_store.py -q`
Expected: collection error, `ImportError: cannot import name 'DeviceCodeStoreContended'`.

Run: `uv run pytest tests/test_redis_backed_stores.py -q`
Expected: collection error, the same `ImportError`.

- [ ] **Step 4: Implement, in `packages/postern-core/src/postern_core/auth/device_codes.py`**

4a. Add `from collections.abc import Callable` to the imports, directly after `from abc import ABC, abstractmethod`.

4b. Directly after `DeviceCodeStoreFull` (after its `self.cap = cap` line and before the `# DeviceCode — the core model.` banner), add:

```python


class DeviceCodeStoreContended(RuntimeError):
    """A store operation that could not settle after a bounded number of tries.

    Two sources, both of which refuse rather than loop. A secondary key --
    the ``user_code`` or the display handle -- whose freshly generated value
    was already taken on every one of ``_SECONDARY_KEY_ATTEMPTS`` tries, which
    at 32**6 pairing codes against a 10,000-code cap means something is wrong
    with the generator rather than unlucky. And a compare-and-set whose
    ``WATCH`` was beaten on every one of ``_CLAIM_ATTEMPTS`` tries.

    RAISED RATHER THAN ANSWERED ``False``, where ``consume_device_code``
    answers ``False``. Its caller maps ``False`` onto a response that is true
    whichever way the race went; ``claim_scan`` and ``approve_scanned`` have
    callers that would have to invent a reason, and the handlers record an
    exception's type name in ``audit_log.detail`` already, which is the true
    statement: the store could not decide.
    """


#: How many freshly generated values a secondary key gets before
#: `DeviceCodeStoreContended`. Five is generous: a collision needs a live
#: pairing already holding the same six-character code or 128-bit handle.
_SECONDARY_KEY_ATTEMPTS = 5
```

4c. In `DeviceCodeStoreBase`, directly after the abstract `get_device_code`, add:

```python
    @abstractmethod
    async def get_by_display_handle(self, display_handle: str) -> DeviceCode | None:
        """The live code this display handle keys, or ``None``.

        UNLIKE ``get_device_code``, EXPIRY-FILTERED: the page and the state
        endpoint answer an expired pairing exactly as an unknown one, and
        ``POST /scan`` answers both ``invalid_grant``. The lookup re-reads the
        primary and re-checks that its handle matches and that it has not
        expired, because on Redis the secondary key's TTL can outlive the
        primary's by up to a second under the truncation ``_set_code``
        records.
        """

    @abstractmethod
    async def get_by_user_code(self, user_code: str) -> DeviceCode | None:
        """The live code this stored-form pairing code keys, or ``None``.

        ``user_code`` is the six-character stored form; callers normalise
        first. Expiry-filtered and re-checked for the same reasons as
        ``get_by_display_handle``.
        """
```

and replace the abstract `revoke_device_code`'s one-line docstring `"""Remove a device code (e.g. on explicit cancellation)."""` with:

```python
        """Remove a device code and both of its secondary lookups.

        The only operation that deletes the secondaries early. Consuming a
        code leaves them, so ``POST /scan`` can still find an exchanged row
        and answer ``conflict_exchanged``; otherwise they expire with the
        primary.
        """
```

4d. Directly after `_generate_qr_secret` (added in Task 2), add:

```python


def _live_match(code: DeviceCode | None, attribute: str, presented: str) -> DeviceCode | None:
    """``code`` if it is live and its ``attribute`` is exactly ``presented``.

    The re-check both backends run on a secondary lookup. A secondary entry is
    a pointer, and the primary row is the authority: an empty value, an
    expired row, or a row whose own field no longer names what the pointer was
    looked up by all answer ``None``.
    """
    if code is None or not presented or code.is_expired:
        return None
    if getattr(code, attribute) != presented:
        return None
    return code


def _unused(generate: Callable[[], str], taken: dict[str, str], what: str) -> str:
    """A freshly generated value ``taken`` does not hold, or refuse.

    ``generate`` is passed at each call rather than bound at import, so a test
    can replace ``_generate_user_code`` or ``_generate_display_handle`` on the
    module and force a collision.
    """
    for _ in range(_SECONDARY_KEY_ATTEMPTS):
        value = generate()
        if value not in taken:
            return value
    raise DeviceCodeStoreContended(
        f"{_SECONDARY_KEY_ATTEMPTS} generated {what} values were all already in use"
    )
```

4e. In `InMemoryDeviceCodeStore.__init__`, after `self._max_codes = max_codes`, add the two dicts and, as a new method directly below `__init__`, `_forget`:

```python
        #: Display handle to device code, and stored-form pairing code to
        #: device code. Cleared by `_forget` wherever a code leaves `_codes`.
        self._by_handle: dict[str, str] = {}
        self._by_user_code: dict[str, str] = {}

    def _forget(self, device_code: str) -> DeviceCode | None:
        """Remove a code and its two secondary entries, without yielding.

        Synchronous on purpose: `claim_scan` calls it inside its read-then-write
        and must not suspend there. Each secondary entry is removed only if it
        still points at this code, so a value a later code reused is left
        alone.
        """
        code = self._codes.pop(device_code, None)
        if code is None:
            return None
        if self._by_handle.get(code.display_handle) == device_code:
            del self._by_handle[code.display_handle]
        if self._by_user_code.get(code.user_code) == device_code:
            del self._by_user_code[code.user_code]
        return code
```

4f. In `InMemoryDeviceCodeStore._drop_expired`, replace `del self._codes[device_code]` with `self._forget(device_code)`.

4g. In `InMemoryDeviceCodeStore.create_device_code`: add to the `Raises:` section, after the `DeviceCodeStoreFull` entry,

```python
            DeviceCodeStoreContended: if every generated pairing code or
                display handle collided with a live one.
```

replace

```python
        user_code = _generate_user_code()
```

with

```python
        user_code = _unused(_generate_user_code, self._by_user_code, "user_code")
        display_handle = _unused(_generate_display_handle, self._by_handle, "display handle")
```

replace `display_handle=_generate_display_handle(),` with `display_handle=display_handle,`, and replace

```python
        self._codes[device_code] = code
        heapq.heappush(self._expiry, (expires_at.timestamp(), device_code))
```

with

```python
        self._codes[device_code] = code
        self._by_user_code[user_code] = device_code
        self._by_handle[display_handle] = device_code
        heapq.heappush(self._expiry, (expires_at.timestamp(), device_code))
```

4h. In `InMemoryDeviceCodeStore`, directly after `get_device_code`, add:

```python
    async def get_by_display_handle(self, display_handle: str) -> DeviceCode | None:
        """The live code this display handle keys, or ``None``."""
        device_code = self._by_handle.get(display_handle)
        code = self._codes.get(device_code) if device_code is not None else None
        return _live_match(code, "display_handle", display_handle)

    async def get_by_user_code(self, user_code: str) -> DeviceCode | None:
        """The live code this stored-form pairing code keys, or ``None``."""
        device_code = self._by_user_code.get(user_code)
        code = self._codes.get(device_code) if device_code is not None else None
        return _live_match(code, "user_code", user_code)
```

and replace its `revoke_device_code` body and docstring with:

```python
    async def revoke_device_code(self, device_code: str) -> None:
        """Remove a device code and both of its secondary entries."""
        self._forget(device_code)
```

4i. In `RedisDeviceCodeStore`, directly after `_index_key`, add:

```python
    def _handle_key(self, display_handle: str) -> str:
        """The secondary key a display handle is looked up by.

        A device code is ``secrets.token_urlsafe`` output and never contains
        a colon, so ``device:handle:...`` and ``device:user_code:...`` cannot
        collide with ``_key``'s ``device:<device_code>``.
        """
        return f"{self._prefix}device:handle:{display_handle}"

    def _user_code_key(self, user_code: str) -> str:
        """The secondary key a stored-form pairing code is looked up by."""
        return f"{self._prefix}device:user_code:{user_code}"

    def _secondary_keys(self, code: DeviceCode) -> list[str]:
        """Both secondary keys a stored code owns. A record written before
        display handles existed owns only the second."""
        keys = [self._user_code_key(code.user_code)]
        if code.display_handle:
            keys.append(self._handle_key(code.display_handle))
        return keys

    async def _claim_secondary(
        self,
        key_for: Callable[[str], str],
        generate: Callable[[], str],
        device_code: str,
        ttl_seconds: int,
        what: str,
    ) -> str:
        """Claim a fresh secondary key with ``SET NX EX``, or refuse.

        ``NX`` IS THE UNIQUENESS CHECK, and there is no other. Reading the key
        and then setting it would let two replicas both find it free and both
        write, and the second writer's pointer would silently re-home the
        first pairing's ``user_code``. ``EX`` in the same command means a key
        without a TTL cannot exist even if the connection drops mid-create.
        """
        for _ in range(_SECONDARY_KEY_ATTEMPTS):
            value = generate()
            if await self._redis.set(key_for(value), device_code, nx=True, ex=ttl_seconds):
                return value
        raise DeviceCodeStoreContended(
            f"{_SECONDARY_KEY_ATTEMPTS} generated {what} values were all already in use"
        )
```

4j. In `RedisDeviceCodeStore.create_device_code`: add to `Raises:`, after the `DeviceCodeStoreFull` entry,

```python
            DeviceCodeStoreContended: if every generated pairing code or
                display handle was already a live secondary key.

        THE SECONDARY KEYS ARE CLAIMED BEFORE THE PRIMARY IS WRITTEN, so a
        collision is resolved by regenerating the value rather than by
        rewriting a stored row. Their TTL is the requested lifetime in whole
        seconds; the primary's is recomputed and truncated by ``_set_code``,
        so the two can differ by up to a second, which is why both lookups
        re-check the primary.
```

then replace

```python
        device_code = _generate_device_code()
        user_code = _generate_user_code()
        expires_in = expires_in or self._default_ttl
```

with

```python
        device_code = _generate_device_code()
        expires_in = expires_in or self._default_ttl
        secondary_ttl = max(1, int(expires_in))
        user_code = await self._claim_secondary(
            self._user_code_key, _generate_user_code, device_code, secondary_ttl, "user_code"
        )
        display_handle = await self._claim_secondary(
            self._handle_key, _generate_display_handle, device_code, secondary_ttl, "display handle"
        )
```

and replace `display_handle=_generate_display_handle(),` with `display_handle=display_handle,`.

4k. In `RedisDeviceCodeStore`, directly after `get_device_code`, add:

```python
    async def get_by_display_handle(self, display_handle: str) -> DeviceCode | None:
        """The live code this display handle keys, or ``None``."""
        if not display_handle:
            return None
        device_code = await self._redis.get(self._handle_key(display_handle))
        if device_code is None:
            return None
        return _live_match(
            await self.get_device_code(device_code), "display_handle", display_handle
        )

    async def get_by_user_code(self, user_code: str) -> DeviceCode | None:
        """The live code this stored-form pairing code keys, or ``None``."""
        if not user_code:
            return None
        device_code = await self._redis.get(self._user_code_key(user_code))
        if device_code is None:
            return None
        return _live_match(await self.get_device_code(device_code), "user_code", user_code)
```

4l. Replace `RedisDeviceCodeStore.revoke_device_code` (signature, docstring and body) with:

```python
    async def revoke_device_code(self, device_code: str) -> None:
        """Remove a device code, its index member and its two secondary keys.

        The index member, or the cap counts codes that no longer exist and a
        service that revokes normally would refuse pairings it has room for.
        The secondary keys, or a revoked pairing's ``user_code`` would still
        resolve until its TTL ran out -- to nothing, since the lookup re-reads
        the primary, but at the cost of holding the value out of reuse.

        The row is read first to learn the secondary names. A row that is
        already gone leaves its secondary keys to their own TTL, which is
        what they would have done anyway.
        """
        stored = await self.get_device_code(device_code)
        pipe = self._redis.pipeline()
        pipe.delete(self._key(device_code))
        pipe.zrem(self._index_key(), device_code)
        if stored is not None:
            for key in self._secondary_keys(stored):
                pipe.delete(key)
        await pipe.execute()
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `uv run pytest tests/test_device_code_pairing_store.py tests/test_redis_backed_stores.py tests/test_device_grant.py tests/test_confirm_rate_limit.py -q`
Expected: all pass.

- [ ] **Step 6: Format, then run the gate**

Run: `uv run ruff format packages services tests && make ci`
Expected: exit 0.

- [ ] **Step 7: Commit**

```bash
git add packages/postern-core/src/postern_core/auth/device_codes.py tests/test_device_code_pairing_store.py tests/test_redis_backed_stores.py
git commit -m "feat(core): look device codes up by display handle and by user code" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 4: Claim a scan and approve a scanned code by compare-and-set

Spec section 1, `claim_scan` with its six `ScanClaim` results and `approve_scanned`. Both are transactions on the primary key, modelled on `consume_device_code`. `update_device_code` and `approve_device_code` still exist after this task; Task 8 removes them together with their last callers.

**Files:**
- Modify: `packages/postern-core/src/postern_core/auth/device_codes.py` (`import enum`; new `ScanClaim`, `_scan_verdict`, `_may_approve`; abstract `claim_scan`, `approve_scanned`; both backends' `claim_scan` and `approve_scanned`)
- Test: `tests/test_device_code_pairing_store.py` (imports; new classes `TestClaimScan`, `TestApproveScanned`)
- Test: `tests/test_redis_backed_stores.py` (import; six new tests)

- [ ] **Step 1: Write the failing in-memory tests**

In `tests/test_device_code_pairing_store.py`, add `import asyncio` as the first line of the standard-library imports (above `import base64`), add `ScanClaim,` as the last name inside the `from postern_core.auth.device_codes import (...)` block, and append at the end of the file:

```python


# ---------------------------------------------------------------------------
# The two compare-and-set writes.
# ---------------------------------------------------------------------------

ALICE = "cust_a11ce"
BOB = "cust_b0b0"


class TestClaimScan:
    async def test_the_first_scan_is_claimed_and_recorded(self) -> None:
        store = InMemoryDeviceCodeStore()
        code = await _create(store)

        assert await store.claim_scan(code.device_code, ALICE) is ScanClaim.CLAIMED

        stored = await store.get_device_code(code.device_code)
        assert stored is not None
        assert stored.scanned_by == ALICE
        assert stored.scanned_at is not None
        assert stored.approved is False

    async def test_a_repeat_by_the_same_customer_is_already_mine_and_writes_nothing(
        self,
    ) -> None:
        store = InMemoryDeviceCodeStore()
        code = await _create(store)
        await store.claim_scan(code.device_code, ALICE)
        before = await store.get_device_code(code.device_code)

        assert await store.claim_scan(code.device_code, ALICE) is ScanClaim.ALREADY_MINE
        assert await store.get_device_code(code.device_code) == before

    async def test_a_repeat_after_approval_is_approved_mine(self) -> None:
        store = InMemoryDeviceCodeStore()
        code = await _create(store)
        await store.claim_scan(code.device_code, ALICE)
        assert await store.approve_scanned(code.device_code, ALICE) is True
        before = await store.get_device_code(code.device_code)

        assert await store.claim_scan(code.device_code, ALICE) is ScanClaim.APPROVED_MINE
        assert await store.get_device_code(code.device_code) == before

    async def test_another_customer_on_an_unexchanged_code_revokes_it(self) -> None:
        """The session-swap defence: B scanned first, A's scan ends the pairing."""
        store = InMemoryDeviceCodeStore()
        code = await _create(store)
        await store.claim_scan(code.device_code, BOB)

        assert await store.claim_scan(code.device_code, ALICE) is ScanClaim.CONFLICT_REVOKED

        assert await store.get_device_code(code.device_code) is None
        assert await store.get_by_user_code(code.user_code) is None
        assert code.display_handle not in store._by_handle

    async def test_another_customer_on_an_approved_unexchanged_code_revokes_it_too(
        self,
    ) -> None:
        store = InMemoryDeviceCodeStore()
        code = await _create(store)
        await store.claim_scan(code.device_code, BOB)
        await store.approve_scanned(code.device_code, BOB)

        assert await store.claim_scan(code.device_code, ALICE) is ScanClaim.CONFLICT_REVOKED
        assert await store.get_device_code(code.device_code) is None

    async def test_another_customer_on_an_exchanged_code_leaves_it_unchanged(self) -> None:
        store = InMemoryDeviceCodeStore()
        code = await _create(store)
        await store.claim_scan(code.device_code, BOB)
        await store.approve_scanned(code.device_code, BOB)
        await store.consume_device_code(code.device_code)
        before = await store.get_device_code(code.device_code)

        assert await store.claim_scan(code.device_code, ALICE) is ScanClaim.CONFLICT_EXCHANGED
        assert await store.get_device_code(code.device_code) == before

    async def test_a_missing_code_is_gone(self) -> None:
        store = InMemoryDeviceCodeStore()
        assert await store.claim_scan("never-existed", ALICE) is ScanClaim.GONE

    async def test_an_expired_code_is_gone_and_unclaimed(self) -> None:
        store = InMemoryDeviceCodeStore()
        code = await _create(store)
        past = datetime.now(UTC) - timedelta(seconds=1)
        store._codes[code.device_code] = replace(code, expires_at=past)

        assert await store.claim_scan(code.device_code, ALICE) is ScanClaim.GONE
        stored = await store.get_device_code(code.device_code)
        assert stored is not None and stored.scanned_by == ""

    async def test_a_previous_release_approval_with_no_scan_is_gone(self) -> None:
        store = InMemoryDeviceCodeStore()
        code = await _create(store)
        store._codes[code.device_code] = replace(code, approved=True, customer_ref=BOB)

        assert await store.claim_scan(code.device_code, ALICE) is ScanClaim.GONE

    async def test_two_concurrent_first_scans_claim_once(self) -> None:
        store = InMemoryDeviceCodeStore()
        code = await _create(store)

        results = await asyncio.gather(
            store.claim_scan(code.device_code, ALICE),
            store.claim_scan(code.device_code, ALICE),
        )

        assert sorted(r.value for r in results) == ["already_mine", "claimed"]


class TestApproveScanned:
    async def test_the_scanner_approves_and_becomes_the_customer(self) -> None:
        store = InMemoryDeviceCodeStore()
        code = await _create(store)
        await store.claim_scan(code.device_code, ALICE)

        assert await store.approve_scanned(code.device_code, ALICE) is True

        stored = await store.get_device_code(code.device_code)
        assert stored is not None
        assert stored.approved is True
        assert stored.approved_at is not None
        assert stored.customer_ref == ALICE
        assert stored.scanned_by == ALICE

    async def test_an_unscanned_code_is_refused(self) -> None:
        store = InMemoryDeviceCodeStore()
        code = await _create(store)

        assert await store.approve_scanned(code.device_code, ALICE) is False
        stored = await store.get_device_code(code.device_code)
        assert stored is not None and stored.approved is False

    async def test_a_code_another_customer_scanned_is_refused(self) -> None:
        store = InMemoryDeviceCodeStore()
        code = await _create(store)
        await store.claim_scan(code.device_code, BOB)

        assert await store.approve_scanned(code.device_code, ALICE) is False
        stored = await store.get_device_code(code.device_code)
        assert stored is not None and stored.approved is False and stored.customer_ref == ""

    async def test_an_approved_code_is_refused(self) -> None:
        store = InMemoryDeviceCodeStore()
        code = await _create(store)
        await store.claim_scan(code.device_code, ALICE)
        await store.approve_scanned(code.device_code, ALICE)

        assert await store.approve_scanned(code.device_code, ALICE) is False

    async def test_an_expired_code_is_refused(self) -> None:
        store = InMemoryDeviceCodeStore()
        code = await _create(store)
        await store.claim_scan(code.device_code, ALICE)
        scanned = await store.get_device_code(code.device_code)
        assert scanned is not None
        past = datetime.now(UTC) - timedelta(seconds=1)
        store._codes[code.device_code] = replace(scanned, expires_at=past)

        assert await store.approve_scanned(code.device_code, ALICE) is False

    async def test_a_missing_code_is_refused(self) -> None:
        store = InMemoryDeviceCodeStore()
        assert await store.approve_scanned("never-existed", ALICE) is False

    async def test_two_concurrent_approvals_approve_exactly_once(self) -> None:
        store = InMemoryDeviceCodeStore()
        code = await _create(store)
        await store.claim_scan(code.device_code, ALICE)

        won = await asyncio.gather(
            store.approve_scanned(code.device_code, ALICE),
            store.approve_scanned(code.device_code, ALICE),
        )

        assert sorted(won) == [False, True]
```

- [ ] **Step 2: Write the failing Redis tests**

In `tests/test_redis_backed_stores.py`, add `ScanClaim,` directly after `RedisDeviceCodeStore,` inside the `from postern_core.auth.device_codes import (...)` block, and append after `test_a_generator_that_only_collides_raises_rather_than_looping` (Task 3's last test):

```python


async def test_every_non_conflict_scan_result_against_a_real_server(stores: RedisStores) -> None:
    """``claimed``, ``already_mine`` and ``approved_mine``, each read back
    through a second connection, and none of them moves the expiry."""
    writer = stores.device_codes()
    reader = stores.device_codes()
    code = await _create(writer, expires_in=120)
    ttl_before = await writer._redis.ttl(writer._key(code.device_code))

    assert await writer.claim_scan(code.device_code, OWNER) is ScanClaim.CLAIMED
    seen = await reader.get_device_code(code.device_code)
    assert seen is not None and seen.scanned_by == OWNER and seen.scanned_at is not None

    assert await reader.claim_scan(code.device_code, OWNER) is ScanClaim.ALREADY_MINE
    assert await reader.approve_scanned(code.device_code, OWNER) is True
    assert await writer.claim_scan(code.device_code, OWNER) is ScanClaim.APPROVED_MINE

    ttl_after = await writer._redis.ttl(writer._key(code.device_code))
    assert ttl_before - 1 <= ttl_after <= ttl_before, "a claim or an approval moved the expiry"


async def test_a_conflict_on_an_unexchanged_code_revokes_all_of_it(stores: RedisStores) -> None:
    store = stores.device_codes()
    code = await _create(store)
    assert await store.claim_scan(code.device_code, OTHER) is ScanClaim.CLAIMED

    assert await store.claim_scan(code.device_code, OWNER) is ScanClaim.CONFLICT_REVOKED

    assert await store._redis.exists(store._key(code.device_code)) == 0
    assert await store._redis.exists(store._user_code_key(code.user_code)) == 0
    assert await store._redis.exists(store._handle_key(code.display_handle)) == 0
    assert await store._redis.zscore(store._index_key(), code.device_code) is None


async def test_a_conflict_on_an_exchanged_code_writes_nothing(stores: RedisStores) -> None:
    store = stores.device_codes()
    code = await _create(store)
    await store.claim_scan(code.device_code, OTHER)
    await store.approve_scanned(code.device_code, OTHER)
    await store.consume_device_code(code.device_code)
    before = await store._redis.get(store._key(code.device_code))

    assert await store.claim_scan(code.device_code, OWNER) is ScanClaim.CONFLICT_EXCHANGED
    assert await store._redis.get(store._key(code.device_code)) == before


async def test_a_missing_or_expired_code_is_gone(stores: RedisStores) -> None:
    store = stores.device_codes()
    assert await store.claim_scan("never-existed", OWNER) is ScanClaim.GONE

    code = await _create(store)
    stale = dataclasses.replace(code, expires_at=datetime.now(UTC) - timedelta(seconds=1))
    await store._redis.set(store._key(code.device_code), stale.to_json(), keepttl=True)
    assert await store.claim_scan(code.device_code, OWNER) is ScanClaim.GONE


async def test_approve_scanned_refuses_every_shape_it_must(stores: RedisStores) -> None:
    store = stores.device_codes()

    unscanned = await _create(store)
    assert await store.approve_scanned(unscanned.device_code, OWNER) is False

    someone_elses = await _create(store)
    await store.claim_scan(someone_elses.device_code, OTHER)
    assert await store.approve_scanned(someone_elses.device_code, OWNER) is False

    approved = await _create(store)
    await store.claim_scan(approved.device_code, OWNER)
    assert await store.approve_scanned(approved.device_code, OWNER) is True
    assert await store.approve_scanned(approved.device_code, OWNER) is False

    expired = await _create(store)
    await store.claim_scan(expired.device_code, OWNER)
    scanned = await store.get_device_code(expired.device_code)
    assert scanned is not None
    stale = dataclasses.replace(scanned, expires_at=datetime.now(UTC) - timedelta(seconds=1))
    await store._redis.set(store._key(expired.device_code), stale.to_json(), keepttl=True)
    assert await store.approve_scanned(expired.device_code, OWNER) is False

    for refused in (unscanned, someone_elses):
        stored = await store.get_device_code(refused.device_code)
        assert stored is not None and stored.approved is False and stored.customer_ref == ""


async def test_two_concurrent_approvals_on_one_key_approve_exactly_once(
    stores: RedisStores,
) -> None:
    """Two replicas, one Redis: the server refuses the second writer."""
    first = stores.device_codes()
    second = stores.device_codes()
    code = await _create(first)
    await first.claim_scan(code.device_code, OWNER)

    won = await asyncio.gather(
        first.approve_scanned(code.device_code, OWNER),
        second.approve_scanned(code.device_code, OWNER),
    )

    assert sorted(won) == [False, True]
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `uv run pytest tests/test_device_code_pairing_store.py -q`
Expected: collection error, `ImportError: cannot import name 'ScanClaim'`.

Run: `uv run pytest tests/test_redis_backed_stores.py -q`
Expected: collection error, the same `ImportError`.

- [ ] **Step 4: Implement, in `packages/postern-core/src/postern_core/auth/device_codes.py`**

4a. Add `import enum` to the imports, directly after `import dataclasses`.

4b. Directly after `_SECONDARY_KEY_ATTEMPTS = 5` (Task 3), add:

```python


class ScanClaim(enum.Enum):
    """What ``claim_scan`` found and did, in one transaction.

    Exactly one per call. ``POST /scan`` maps each onto a response and an
    ``audit_log.detail``; the mapping lives there, and this type says only
    what happened to the row.
    """

    #: ``scanned_by`` was empty and the code unexpired and unapproved. It now
    #: names this customer, with ``scanned_at`` set.
    CLAIMED = "claimed"
    #: This customer already holds the scan and the code is unapproved.
    #: Nothing written. A retried ``POST /scan`` inside the token window.
    ALREADY_MINE = "already_mine"
    #: This customer holds the scan and has approved. Nothing written.
    APPROVED_MINE = "approved_mine"
    #: Another customer holds the scan and the code was never exchanged. The
    #: pairing is revoked in the same transaction: the session-swap defence.
    CONFLICT_REVOKED = "conflict_revoked"
    #: Another customer holds the scan and the code was already exchanged.
    #: Nothing written, because revoking a spent code recalls nothing.
    CONFLICT_EXCHANGED = "conflict_exchanged"
    #: The row is missing or expired.
    GONE = "gone"
```

4c. Directly after `_unused` (Task 3) and before `class InMemoryDeviceCodeStore`, add:

```python


def _scan_verdict(code: DeviceCode, customer_ref: str) -> ScanClaim:
    """Which ``ScanClaim`` a stored code earns, decided from the row alone.

    One pure function both backends call inside their read-then-write, so the
    two cannot disagree about the table in ``dev-docs/qr-page-spec.md``
    section 1. A code can only be approved by the customer in ``scanned_by``
    (``_may_approve``), so "scanned or approved by someone else" is the one
    test ``scanned_by != customer_ref``.

    AN UNSCANNED CODE THAT IS ALREADY APPROVED IS ``GONE``. Nothing this
    release writes produces one; only a record the previous release approved
    does, and that record has no ``qr_secret`` either, so ``POST /scan``
    refuses it earlier. Answering ``GONE`` keeps this function total without
    inventing a seventh result.
    """
    if code.is_expired:
        return ScanClaim.GONE
    if not code.scanned_by:
        return ScanClaim.GONE if code.approved else ScanClaim.CLAIMED
    if code.scanned_by == customer_ref:
        return ScanClaim.APPROVED_MINE if code.approved else ScanClaim.ALREADY_MINE
    if code.exchanged_at is None:
        return ScanClaim.CONFLICT_REVOKED
    return ScanClaim.CONFLICT_EXCHANGED


def _may_approve(code: DeviceCode, customer_ref: str) -> bool:
    """Whether ``approve_scanned`` may approve this code for this customer."""
    return (
        bool(customer_ref)
        and not code.is_expired
        and not code.approved
        and code.scanned_by == customer_ref
    )
```

4d. In `DeviceCodeStoreBase`, directly after the abstract `consume_device_code` and before the abstract `revoke_device_code`, add:

```python
    @abstractmethod
    async def claim_scan(self, device_code: str, customer_ref: str) -> ScanClaim:
        """Record the first scan of a code, or say why this one is not it.

        A COMPARE-AND-SET, modelled on ``consume_device_code``: one
        transaction reads the row, decides with ``_scan_verdict``, and writes
        only for ``CLAIMED`` (``scanned_by``, ``scanned_at``) and
        ``CONFLICT_REVOKED`` (the whole pairing, secondaries included). Every
        other result writes nothing. The same atomicity contract as
        ``consume_device_code`` holds, for the same reason: two phones
        scanning one QR on two replicas must not both win.

        Raises:
            DeviceCodeStoreContended: if the transaction could not settle.
        """

    @abstractmethod
    async def approve_scanned(self, device_code: str, customer_ref: str) -> bool:
        """Approve a code for the customer who scanned it. ``True`` to one caller.

        Sets ``approved``, ``approved_at`` and ``customer_ref`` only when the
        code is unexpired, unapproved and ``scanned_by == customer_ref``,
        in one compare-and-set; answers ``False`` otherwise and writes
        nothing. It replaces the read-check-write that let two replicas both
        approve and the last writer's ``customer_ref`` win.

        Raises:
            DeviceCodeStoreContended: if the transaction could not settle.
        """
```

4e. In `InMemoryDeviceCodeStore`, directly before its `revoke_device_code`, add:

```python
    async def claim_scan(self, device_code: str, customer_ref: str) -> ScanClaim:
        """Record the first scan, or say why this one is not it.

        ATOMIC BY NOT YIELDING, for the reason ``consume_device_code`` gives:
        no ``await`` between the read, ``_scan_verdict`` and the write, and
        ``_forget`` is synchronous for exactly this caller.
        """
        existing = self._codes.get(device_code)
        if existing is None:
            return ScanClaim.GONE
        claim = _scan_verdict(existing, customer_ref)
        if claim is ScanClaim.CLAIMED:
            self._codes[device_code] = dataclasses.replace(
                existing, scanned_by=customer_ref, scanned_at=datetime.now(UTC)
            )
        elif claim is ScanClaim.CONFLICT_REVOKED:
            self._forget(device_code)
        return claim

    async def approve_scanned(self, device_code: str, customer_ref: str) -> bool:
        """Approve for the scanner, atomically by not yielding."""
        existing = self._codes.get(device_code)
        if existing is None or not _may_approve(existing, customer_ref):
            return False
        self._codes[device_code] = dataclasses.replace(
            existing, approved=True, approved_at=datetime.now(UTC), customer_ref=customer_ref
        )
        return True
```

4f. In `RedisDeviceCodeStore`, directly before its `revoke_device_code` (after `consume_device_code`), add:

```python
    async def claim_scan(self, device_code: str, customer_ref: str) -> ScanClaim:
        """Record the first scan, or say why this one is not it.

        ``WATCH``/``MULTI`` on the primary, the shape ``consume_device_code``
        uses and for its reasons, with ``KEEPTTL`` on the claim so the scan
        does not move the expiry. ``CONFLICT_REVOKED`` deletes the primary,
        its index member and both secondary keys inside the same ``MULTI``,
        so no replica can observe the pairing half-revoked. A value that will
        not deserialize is ``GONE``: a row this store cannot read is not one
        a scan may claim.
        """
        from redis.exceptions import WatchError

        key = self._key(device_code)
        for _ in range(_CLAIM_ATTEMPTS):
            async with self._redis.pipeline(transaction=True) as pipe:
                try:
                    await pipe.watch(key)
                    raw = await pipe.get(key)
                    if raw is None:
                        return ScanClaim.GONE
                    try:
                        code = DeviceCode.from_json(raw)
                    except (KeyError, ValueError, TypeError):
                        logger.warning(
                            "refusing a scan of device code %s: its stored value will not "
                            "deserialize",
                            device_code,
                        )
                        return ScanClaim.GONE
                    claim = _scan_verdict(code, customer_ref)
                    if claim is ScanClaim.CLAIMED:
                        scanned = dataclasses.replace(
                            code, scanned_by=customer_ref, scanned_at=datetime.now(UTC)
                        )
                        pipe.multi()
                        pipe.set(key, scanned.to_json(), keepttl=True)
                        await pipe.execute()
                    elif claim is ScanClaim.CONFLICT_REVOKED:
                        pipe.multi()
                        pipe.delete(key)
                        pipe.zrem(self._index_key(), device_code)
                        for secondary in self._secondary_keys(code):
                            pipe.delete(secondary)
                        await pipe.execute()
                    return claim
                except WatchError:
                    continue
        raise DeviceCodeStoreContended(
            f"a scan claim was beaten by another writer {_CLAIM_ATTEMPTS} times"
        )

    async def approve_scanned(self, device_code: str, customer_ref: str) -> bool:
        """Approve for the scanner, with the server settling the race.

        The same ``WATCH``/``MULTI``/``KEEPTTL`` shape as ``claim_scan``. The
        loser of two concurrent approvals retries, reads ``approved`` the
        winner wrote, and answers ``False``.
        """
        from redis.exceptions import WatchError

        key = self._key(device_code)
        for _ in range(_CLAIM_ATTEMPTS):
            async with self._redis.pipeline(transaction=True) as pipe:
                try:
                    await pipe.watch(key)
                    raw = await pipe.get(key)
                    if raw is None:
                        return False
                    try:
                        code = DeviceCode.from_json(raw)
                    except (KeyError, ValueError, TypeError):
                        logger.warning(
                            "refusing to approve device code %s: its stored value will not "
                            "deserialize",
                            device_code,
                        )
                        return False
                    if not _may_approve(code, customer_ref):
                        return False
                    approved = dataclasses.replace(
                        code,
                        approved=True,
                        approved_at=datetime.now(UTC),
                        customer_ref=customer_ref,
                    )
                    pipe.multi()
                    pipe.set(key, approved.to_json(), keepttl=True)
                    await pipe.execute()
                    return True
                except WatchError:
                    continue
        raise DeviceCodeStoreContended(
            f"an approval was beaten by another writer {_CLAIM_ATTEMPTS} times"
        )
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `uv run pytest tests/test_device_code_pairing_store.py tests/test_redis_backed_stores.py tests/test_device_grant.py -q`
Expected: all pass.

- [ ] **Step 6: Format, then run the gate**

Run: `uv run ruff format packages services tests && make ci`
Expected: exit 0.

- [ ] **Step 7: Commit**

```bash
git add packages/postern-core/src/postern_core/auth/device_codes.py tests/test_device_code_pairing_store.py tests/test_redis_backed_stores.py
git commit -m "feat(core): claim a scan and approve a scanned code by compare-and-set" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 5: `POSTERN_DEVICE_APP_LINK_URI`, and the shared-host refusal

Spec section 3: the setting, its default, its `env_inventory` row, and `ConfirmSettings.from_env` refusing to start when the app link's host equals the page's host (hostnames from `urllib.parse.urlsplit`, case-folded).

**Files:**
- Modify: `services/confirm/settings.py` (module docstring; import; new `_app_link_uri`; `ConfirmSettings.device_app_link_uri`; `ConfirmSettings.from_env`)
- Modify: `packages/postern-core/src/postern_core/env_inventory.py` (`INVENTORY` row and its comment)
- Create: `tests/test_confirm_app_link_setting.py`
- Modify: `tests/test_settings_bounds.py` (`TestEveryEnvironmentReadNamesAnInventoriedVariable.test_the_two_inventories_are_the_whole_tree` and `.test_the_counts_the_docstrings_quote`)

- [ ] **Step 1: Write the failing test**

Create `tests/test_confirm_app_link_setting.py`:

```python
"""``POSTERN_DEVICE_APP_LINK_URI``: the base the pairing QR encodes.

Section 3 of ``dev-docs/qr-page-spec.md``. The page and the app link are two
URIs, and the app link's host must not be the page's: a phone camera handed a
URL on the page's host opens the browser page instead of the bank app, so the
pairing could never reach ``POST /scan``. ``ConfirmSettings.from_env`` refuses
that configuration at startup.
"""

from __future__ import annotations

import pytest
from postern_core.env_inventory import INVENTORY

from services.confirm.settings import ConfirmSettings

PAGE = "POSTERN_DEVICE_VERIFICATION_URI"
LINK = "POSTERN_DEVICE_APP_LINK_URI"
DEFAULT_LINK = "https://app.postern.internal/pair"


@pytest.fixture(autouse=True)
def _unset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(PAGE, raising=False)
    monkeypatch.delenv(LINK, raising=False)


def test_the_field_default_is_the_local_placeholder() -> None:
    assert ConfirmSettings().device_app_link_uri == DEFAULT_LINK


def test_from_env_takes_the_same_default() -> None:
    assert ConfirmSettings.from_env().device_app_link_uri == DEFAULT_LINK


def test_from_env_reads_the_variable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(LINK, "https://pair.bank.test/app")
    assert ConfirmSettings.from_env().device_app_link_uri == "https://pair.bank.test/app"


def test_the_variable_is_inventoried_as_a_confirm_string() -> None:
    rows = [entry for entry in INVENTORY if entry.name == LINK]
    assert len(rows) == 1
    assert rows[0].kind == "string"
    assert rows[0].services == ("confirm",)


@pytest.mark.parametrize(
    ("page", "link"),
    [
        pytest.param("https://auth.bank.test/verify", "https://auth.bank.test/pair", id="same"),
        pytest.param(
            "https://auth.bank.test/verify", "https://AUTH.Bank.Test/pair", id="case only"
        ),
        pytest.param(
            "https://auth.bank.test/verify", "https://auth.bank.test:8443/pair", id="port only"
        ),
    ],
)
def test_a_shared_host_refuses_to_start(
    monkeypatch: pytest.MonkeyPatch, page: str, link: str
) -> None:
    monkeypatch.setenv(PAGE, page)
    monkeypatch.setenv(LINK, link)
    with pytest.raises(ValueError, match=LINK) as refused:
        ConfirmSettings.from_env()
    assert PAGE in str(refused.value)


def test_a_page_moved_onto_the_default_app_link_host_refuses(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Either variable can be the one that collides."""
    monkeypatch.setenv(PAGE, "https://app.postern.internal/verify")
    with pytest.raises(ValueError, match=LINK):
        ConfirmSettings.from_env()


def test_two_different_hosts_start(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(PAGE, "https://auth.bank.test/verify")
    monkeypatch.setenv(LINK, "https://app.bank.test/pair")
    settings = ConfirmSettings.from_env()
    assert settings.device_verification_uri == "https://auth.bank.test/verify"
    assert settings.device_app_link_uri == "https://app.bank.test/pair"
```

- [ ] **Step 2: Run it to verify it fails**

Run: `uv run pytest tests/test_confirm_app_link_setting.py -q`
Expected: FAIL. `test_the_field_default_is_the_local_placeholder` with `AttributeError: 'ConfirmSettings' object has no attribute 'device_app_link_uri'`; `test_the_variable_is_inventoried_as_a_confirm_string` with `assert 0 == 1`; the refusal tests with `Failed: DID NOT RAISE <class 'ValueError'>`.

- [ ] **Step 3: Implement the setting, in `services/confirm/settings.py`**

3a. In the module docstring, replace

```
- ``device_verification_uri`` — base URI for the user verification page.
  The QR code encodes this + ``user_code``; the mobile app deep-links to it.
```

with

```
- ``device_verification_uri`` -- base URI of the browser's pairing page.
  ``verification_uri_complete`` is this plus ``?d=`` and the pairing's display
  handle.
- ``device_app_link_uri`` -- the operator's universal-link / app-link base.
  The QR on the pairing page encodes this plus ``user_code`` and a rotation
  token, so a phone camera hands it to the bank app. Its host must differ from
  ``device_verification_uri``'s, and ``from_env`` refuses to start otherwise.
```

3b. Add `from urllib.parse import urlsplit` directly after `from dataclasses import dataclass`.

3c. Directly after `_device_code_ttl` and before `@dataclass(frozen=True)`, add:

```python
@@SNIP|t5|services/confirm/settings.py|def _app_link_uri(page_uri: str) -> str:|@dataclass(frozen=True)@@
```

3d. In `ConfirmSettings`, directly after the `device_verification_uri` field, add:

```python
    # The base of the app link the pairing QR encodes. A placeholder host for
    # local work, like the field above; a deployment owes its own, with the
    # Apple associated-domains and Android asset-links files that make a
    # camera open the bank app. `_app_link_uri` refuses one on the page's host.
    device_app_link_uri: str = "https://app.postern.internal/pair"
```

3e. In `ConfirmSettings.from_env`, make the page URI a local read first. Replace

```python
    def from_env(cls) -> "ConfirmSettings":
        return cls(
```

with

```python
    def from_env(cls) -> "ConfirmSettings":
        device_verification_uri = os.environ.get(
            "POSTERN_DEVICE_VERIFICATION_URI",
            "https://auth.postern.internal/verify",
        )
        return cls(
```

and replace

```python
            device_verification_uri=os.environ.get(
                "POSTERN_DEVICE_VERIFICATION_URI",
                "https://auth.postern.internal/verify",
            ),
```

with

```python
            device_verification_uri=device_verification_uri,
            device_app_link_uri=_app_link_uri(device_verification_uri),
```

- [ ] **Step 4: Inventory the variable, in `packages/postern-core/src/postern_core/env_inventory.py`**

Add the row directly after `EnvVar("POSTERN_DATABASE_URL", "string", EVERYWHERE),`:

```python
    EnvVar("POSTERN_DEVICE_APP_LINK_URI", "string", ("confirm",)),
```

and replace the comment above `INVENTORY`

```python
#: Generated from the syntax tree on 2026-09-27 rather than typed, and pinned
#: against it by `tests/test_settings_bounds.py` on every run. 65 rows since
#: 2026-09-29: 26 strings (24 settings plus this guard's own two lists), 36
#: numbers, 3 flags. The eight that arrived on that date are the
#: ``POSTERN_VAULT_*`` family, below the device-code block.
```

with

```python
#: Generated from the syntax tree on 2026-09-27 rather than typed, and pinned
#: against it by `tests/test_settings_bounds.py` on every run. 66 rows since
#: 2026-09-30: 27 strings (25 settings plus this guard's own two lists), 36
#: numbers, 3 flags. The eight ``POSTERN_VAULT_*`` rows below the device-code
#: block arrived on 2026-09-29; ``POSTERN_DEVICE_APP_LINK_URI`` arrived on
#: 2026-09-30 with the QR page.
```

- [ ] **Step 5: Move the pinned counts, in `tests/test_settings_bounds.py`**

- In `test_the_two_inventories_are_the_whole_tree`: the docstring `"""65 variables, 26 read directly and 39 through a reader, disjoint."""` becomes `"""66 variables, 27 read directly and 39 through a reader, disjoint."""`, and `assert len(KNOWN_ENV) == 65` becomes `assert len(KNOWN_ENV) == 66`.
- In `test_the_counts_the_docstrings_quote`: `assert len(KNOWN_ENV) == 65` becomes `== 66`, `assert len(READ_AS_STRING) == 26` becomes `== 27`, and `assert len(names_read_by("confirm")) == 49` becomes `== 50`. Nothing else in that test moves.

- [ ] **Step 6: Run the tests to verify they pass**

Run: `uv run pytest tests/test_confirm_app_link_setting.py tests/test_settings_bounds.py tests/test_unknown_env_guard.py tests/test_zt8_no_hardcoded_external_endpoints.py -q`
Expected: all pass.

- [ ] **Step 7: Format, then run the gate**

Run: `uv run ruff format packages services tests && make ci`
Expected: exit 0.

- [ ] **Step 8: Commit**

```bash
git add services/confirm/settings.py packages/postern-core/src/postern_core/env_inventory.py tests/test_confirm_app_link_setting.py tests/test_settings_bounds.py
git commit -m "feat(confirm): add POSTERN_DEVICE_APP_LINK_URI and refuse a host shared with the page" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 6: Rate limits for the QR page routes and `POST /scan`

Spec section 8: an explicit entry per new path in the per-address table, each a setting with an `env_inventory` row, and `/scan` at 10 per customer. The paths do not exist yet; a limit on a path nobody serves is harmless, and landing the table first keeps Tasks 9 and 10 about behaviour.

**Files:**
- Modify: `services/confirm/rate_limit.py` (`DEFAULT_LIMITS` and its comment, `limits_from_settings`, `route_key` docstring)
- Modify: `services/confirm/customer_rate_limit.py` (`DEFAULT_CUSTOMER_LIMITS`, `customer_limits_from_settings`)
- Modify: `services/confirm/settings.py` (seven fields, seven `from_env` reads)
- Modify: `services/confirm/main.py` (`create_confirm_app`'s two limiter constructions)
- Modify: `packages/postern-core/src/postern_core/env_inventory.py` (seven rows, the row-count comment)
- Test: `tests/test_confirm_rate_limit.py`, `tests/test_confirm_customer_rate_limit.py`, `tests/test_settings_bounds.py`

- [ ] **Step 1: Write the failing tests**

1a. In `tests/test_confirm_rate_limit.py`, class `TestTheConfiguredLimits`, replace `test_every_public_path_carries_a_limit` with the following two tests:

```python
    def test_every_public_path_carries_a_limit(self) -> None:
        for path in (
            "/device_authorization",
            "/token",
            "/approve",
            "/challenges/approve",
            "/scan",
            "/verify",
            "/verify/qr.svg",
            "/verify/state",
            "/verify.js",
            "/verify.css",
        ):
            assert path in DEFAULT_LIMITS

    def test_the_qr_page_limits_are_the_specs(self) -> None:
        """Section 8 of ``dev-docs/qr-page-spec.md``: the image and the state
        are polled every two seconds, 30 a minute per tab, so 300 is ten tabs
        behind one address; everything else is loaded once per page."""
        assert DEFAULT_LIMITS["/verify"] == Limit(60, RATE_LIMIT_WINDOW_SECONDS)
        assert DEFAULT_LIMITS["/verify/qr.svg"] == Limit(300, RATE_LIMIT_WINDOW_SECONDS)
        assert DEFAULT_LIMITS["/verify/state"] == Limit(300, RATE_LIMIT_WINDOW_SECONDS)
        assert DEFAULT_LIMITS["/verify.js"] == Limit(60, RATE_LIMIT_WINDOW_SECONDS)
        assert DEFAULT_LIMITS["/verify.css"] == Limit(60, RATE_LIMIT_WINDOW_SECONDS)
        assert DEFAULT_LIMITS["/scan"] == Limit(60, RATE_LIMIT_WINDOW_SECONDS)
```

1b. In the same file, class `TestTheLimitsAreSettableWithoutACodeChange`, extend `NAMES` so it ends:

```python
        ("POSTERN_CONFIRM_RATE_LIMIT_DEFAULT", "rate_limit_default"),
        ("POSTERN_CONFIRM_RATE_LIMIT_SCAN", "rate_limit_scan"),
        ("POSTERN_CONFIRM_RATE_LIMIT_VERIFY", "rate_limit_verify"),
        ("POSTERN_CONFIRM_RATE_LIMIT_VERIFY_QR", "rate_limit_verify_qr"),
        ("POSTERN_CONFIRM_RATE_LIMIT_VERIFY_STATE", "rate_limit_verify_state"),
        ("POSTERN_CONFIRM_RATE_LIMIT_VERIFY_JS", "rate_limit_verify_js"),
        ("POSTERN_CONFIRM_RATE_LIMIT_VERIFY_CSS", "rate_limit_verify_css"),
    ]
```

and in its `test_the_defaults_reproduce_the_module_constants_exactly`, make the `limits_from_settings(...)` call:

```python
            limits_from_settings(
                device_authorization=settings.rate_limit_device_authorization,
                token=settings.rate_limit_token,
                approve=settings.rate_limit_approve,
                challenge_approve=settings.rate_limit_challenge_approve,
                scan=settings.rate_limit_scan,
                verify=settings.rate_limit_verify,
                verify_qr=settings.rate_limit_verify_qr,
                verify_state=settings.rate_limit_verify_state,
                verify_js=settings.rate_limit_verify_js,
                verify_css=settings.rate_limit_verify_css,
            )
```

1c. In `tests/test_confirm_customer_rate_limit.py`, class `TestTheShippedCeilings`: in `test_both_defaults_are_ten_a_minute` change `for route in ("/approve", "/challenges/approve"):` to `for route in ("/approve", "/challenges/approve", "/scan"):`, and in `test_the_settings_reproduce_the_defaults_exactly` add `scan=settings.customer_rate_limit_scan,` as the last argument of the `customer_limits_from_settings(...)` call.

1d. In `tests/test_settings_bounds.py`, replace the closing `)` of the `BOUNDED` tuple (the line directly after the `POSTERN_CONFIRM_CUSTOMER_RATE_LIMIT_CHALLENGE_APPROVE` row) with:

```python
    # The QR page's five public routes and ``POST /scan``, through the same
    # `_positive_int`, and the per-customer ceiling on ``/scan``.
    Bounded(
        "POSTERN_CONFIRM_RATE_LIMIT_SCAN", "rate_limit_scan", "confirm", 60, ("0", "-1"), ("1",)
    ),
    Bounded(
        "POSTERN_CONFIRM_RATE_LIMIT_VERIFY", "rate_limit_verify", "confirm", 60, ("0", "-1"), ("1",)
    ),
    Bounded(
        "POSTERN_CONFIRM_RATE_LIMIT_VERIFY_QR",
        "rate_limit_verify_qr",
        "confirm",
        300,
        ("0", "-1"),
        ("1",),
    ),
    Bounded(
        "POSTERN_CONFIRM_RATE_LIMIT_VERIFY_STATE",
        "rate_limit_verify_state",
        "confirm",
        300,
        ("0", "-1"),
        ("1",),
    ),
    Bounded(
        "POSTERN_CONFIRM_RATE_LIMIT_VERIFY_JS",
        "rate_limit_verify_js",
        "confirm",
        60,
        ("0", "-1"),
        ("1",),
    ),
    Bounded(
        "POSTERN_CONFIRM_RATE_LIMIT_VERIFY_CSS",
        "rate_limit_verify_css",
        "confirm",
        60,
        ("0", "-1"),
        ("1",),
    ),
    Bounded(
        "POSTERN_CONFIRM_CUSTOMER_RATE_LIMIT_SCAN",
        "customer_rate_limit_scan",
        "confirm",
        10,
        ("0", "-1"),
        ("1",),
    ),
)
```

(the snippet ends with the tuple's closing `)`), and move the pinned counts: in `test_the_two_inventories_are_the_whole_tree` the docstring becomes `"""73 variables, 27 read directly and 46 through a reader, disjoint."""` and `assert len(KNOWN_ENV) == 66` becomes `== 73`; in `test_the_counts_the_docstrings_quote`, `KNOWN_ENV` 66 becomes 73, `BOUNDED_NAMES` 32 becomes 39, the four-way union 39 becomes 46, and `names_read_by("confirm")` 50 becomes 57.

- [ ] **Step 2: Run them to verify they fail**

Run: `uv run pytest tests/test_confirm_rate_limit.py tests/test_confirm_customer_rate_limit.py tests/test_settings_bounds.py -q`
Expected: FAIL. `test_every_public_path_carries_a_limit` with `assert '/scan' in {...}`; `test_the_qr_page_limits_are_the_specs` with `KeyError: '/verify'`; the six new `NAMES` rows with `AttributeError: 'ConfirmSettings' object has no attribute 'rate_limit_scan'`; the reproduce tests with `TypeError: limits_from_settings() got an unexpected keyword argument 'scan'`; the `BOUNDED` rows and the counts with `AttributeError` and `assert 66 == 73`.

- [ ] **Step 3: Implement the per-address table, in `services/confirm/rate_limit.py`**

3a. In the comment block above `DEFAULT_LIMITS`, directly after the three lines describing ``` ``/challenges/{id}/approve`` -- 60/min ```, add:

```python
#: ``/scan`` -- 60/min. The operator's app, once per pairing, like
#:     ``/approve``; its per-customer ceiling is the one that means something.
#: ``/verify`` -- 60/min. A page load, plus the 12 a minute the noscript
#:     refresh adds for a browser with no script.
#: ``/verify/qr.svg`` and ``/verify/state`` -- 300/min each. The page's
#:     script polls both every two seconds, 30 a minute per open tab, so 300
#:     is ten tabs behind one address.
#: ``/verify.js`` and ``/verify.css`` -- 60/min each. Loaded once per page.
```

and further down the same block change `#: five ``rate_limit_*`` fields, and that setting carries the sentence that` to `#: eleven ``rate_limit_*`` fields, and that setting carries the sentence that`.

3b. `DEFAULT_LIMITS` gains six entries after `"/challenges/approve"`:

```python
    "/scan": Limit(requests=60, window_seconds=60),
    "/verify": Limit(requests=60, window_seconds=60),
    "/verify/qr.svg": Limit(requests=300, window_seconds=60),
    "/verify/state": Limit(requests=300, window_seconds=60),
    "/verify.js": Limit(requests=60, window_seconds=60),
    "/verify.css": Limit(requests=60, window_seconds=60),
```

3c. Replace `limits_from_settings` with:

```python
def limits_from_settings(
    *,
    device_authorization: int,
    token: int,
    approve: int,
    challenge_approve: int,
    scan: int,
    verify: int,
    verify_qr: int,
    verify_state: int,
    verify_js: int,
    verify_css: int,
) -> dict[str, Limit]:
    """Build the per-path limit map from ten per-minute request counts.

    Here rather than in `services/confirm/main.py` so the composition root
    stays assembly, and here rather than in `services/confirm/settings.py` so
    that module keeps importing nothing but ``os`` and ``dataclasses``. The
    path strings are `route_key`'s, which is the one place they are canonical.
    """
    return {
        "/device_authorization": Limit(device_authorization, RATE_LIMIT_WINDOW_SECONDS),
        "/token": Limit(token, RATE_LIMIT_WINDOW_SECONDS),
        "/approve": Limit(approve, RATE_LIMIT_WINDOW_SECONDS),
        "/challenges/approve": Limit(challenge_approve, RATE_LIMIT_WINDOW_SECONDS),
        "/scan": Limit(scan, RATE_LIMIT_WINDOW_SECONDS),
        "/verify": Limit(verify, RATE_LIMIT_WINDOW_SECONDS),
        "/verify/qr.svg": Limit(verify_qr, RATE_LIMIT_WINDOW_SECONDS),
        "/verify/state": Limit(verify_state, RATE_LIMIT_WINDOW_SECONDS),
        "/verify.js": Limit(verify_js, RATE_LIMIT_WINDOW_SECONDS),
        "/verify.css": Limit(verify_css, RATE_LIMIT_WINDOW_SECONDS),
    }
```

3d. In `route_key`'s docstring change `Exact for the three fixed paths.` to `Exact for every fixed path.`

- [ ] **Step 4: Implement the per-customer entry, in `services/confirm/customer_rate_limit.py`**

Replace `DEFAULT_CUSTOMER_LIMITS` with:

```python
DEFAULT_CUSTOMER_LIMITS: dict[str, Limit] = {
    "/approve": Limit(requests=10, window_seconds=RATE_LIMIT_WINDOW_SECONDS),
    "/challenges/approve": Limit(requests=10, window_seconds=RATE_LIMIT_WINDOW_SECONDS),
    # The scan that precedes every pairing approval: one per pairing, the
    # same human sequence as ``/approve``'s derivation above, so the same 10.
    "/scan": Limit(requests=10, window_seconds=RATE_LIMIT_WINDOW_SECONDS),
}
```

and replace `customer_limits_from_settings` with:

```python
def customer_limits_from_settings(
    *,
    approve: int,
    challenge_approve: int,
    scan: int,
) -> dict[str, Limit]:
    """Build the per-path limit map from three per-minute request counts.

    Here rather than in `services/confirm/main.py` so the composition root
    stays assembly, and here rather than in `services/confirm/settings.py` so
    that module keeps importing nothing but ``os`` and ``dataclasses`` -- the
    same split, for the same two reasons, as
    `services/confirm/rate_limit.py`'s ``limits_from_settings``.
    """
    return {
        "/approve": Limit(approve, RATE_LIMIT_WINDOW_SECONDS),
        "/challenges/approve": Limit(challenge_approve, RATE_LIMIT_WINDOW_SECONDS),
        "/scan": Limit(scan, RATE_LIMIT_WINDOW_SECONDS),
    }
```

- [ ] **Step 5: Add the settings, in `services/confirm/settings.py`**

5a. Directly after the field `customer_rate_limit_challenge_approve: int = 10`, add:

```python
@@SNIP|t6|services/confirm/settings.py|    # THE QR PAGE AND ``POST /scan``, added 2026-09-30: six more per-address|    @classmethod@@
```

5b. In `from_env`, directly after the `customer_rate_limit_challenge_approve=_positive_int(...)` argument and before the closing `)` of `cls(`, add:

```python
            rate_limit_scan=_positive_int("POSTERN_CONFIRM_RATE_LIMIT_SCAN", 60),
            rate_limit_verify=_positive_int("POSTERN_CONFIRM_RATE_LIMIT_VERIFY", 60),
            rate_limit_verify_qr=_positive_int("POSTERN_CONFIRM_RATE_LIMIT_VERIFY_QR", 300),
            rate_limit_verify_state=_positive_int("POSTERN_CONFIRM_RATE_LIMIT_VERIFY_STATE", 300),
            rate_limit_verify_js=_positive_int("POSTERN_CONFIRM_RATE_LIMIT_VERIFY_JS", 60),
            rate_limit_verify_css=_positive_int("POSTERN_CONFIRM_RATE_LIMIT_VERIFY_CSS", 60),
            customer_rate_limit_scan=_positive_int("POSTERN_CONFIRM_CUSTOMER_RATE_LIMIT_SCAN", 10),
```

- [ ] **Step 6: Wire them, in `services/confirm/main.py`**

In `create_confirm_app`, the `limits_from_settings(...)` call gains, after `challenge_approve=settings.rate_limit_challenge_approve,`:

```python
                    scan=settings.rate_limit_scan,
                    verify=settings.rate_limit_verify,
                    verify_qr=settings.rate_limit_verify_qr,
                    verify_state=settings.rate_limit_verify_state,
                    verify_js=settings.rate_limit_verify_js,
                    verify_css=settings.rate_limit_verify_css,
```

and the `customer_limits_from_settings(...)` call gains, after `challenge_approve=settings.customer_rate_limit_challenge_approve,`:

```python
                    scan=settings.customer_rate_limit_scan,
```

- [ ] **Step 7: Inventory the seven variables, in `packages/postern-core/src/postern_core/env_inventory.py`**

Add `EnvVar("POSTERN_CONFIRM_CUSTOMER_RATE_LIMIT_SCAN", "number", ("confirm",)),` directly after the `POSTERN_CONFIRM_CUSTOMER_RATE_LIMIT_CHALLENGE_APPROVE` row. Replace the two rows

```python
    EnvVar("POSTERN_CONFIRM_RATE_LIMIT_DEVICE_AUTHORIZATION", "number", ("confirm",)),
    EnvVar("POSTERN_CONFIRM_RATE_LIMIT_TOKEN", "number", ("confirm",)),
```

with

```python
    EnvVar("POSTERN_CONFIRM_RATE_LIMIT_DEVICE_AUTHORIZATION", "number", ("confirm",)),
    EnvVar("POSTERN_CONFIRM_RATE_LIMIT_SCAN", "number", ("confirm",)),
    EnvVar("POSTERN_CONFIRM_RATE_LIMIT_TOKEN", "number", ("confirm",)),
    EnvVar("POSTERN_CONFIRM_RATE_LIMIT_VERIFY", "number", ("confirm",)),
    EnvVar("POSTERN_CONFIRM_RATE_LIMIT_VERIFY_CSS", "number", ("confirm",)),
    EnvVar("POSTERN_CONFIRM_RATE_LIMIT_VERIFY_JS", "number", ("confirm",)),
    EnvVar("POSTERN_CONFIRM_RATE_LIMIT_VERIFY_QR", "number", ("confirm",)),
    EnvVar("POSTERN_CONFIRM_RATE_LIMIT_VERIFY_STATE", "number", ("confirm",)),
```

and replace the comment Task 5 wrote above `INVENTORY` with:

```python
#: Generated from the syntax tree on 2026-09-27 rather than typed, and pinned
#: against it by `tests/test_settings_bounds.py` on every run. 73 rows since
#: 2026-09-30: 27 strings (25 settings plus this guard's own two lists), 43
#: numbers, 3 flags. The eight ``POSTERN_VAULT_*`` rows below the device-code
#: block arrived on 2026-09-29; ``POSTERN_DEVICE_APP_LINK_URI`` and the seven
#: QR-page rate limits arrived on 2026-09-30.
```

- [ ] **Step 8: Run the tests to verify they pass**

Run: `uv run pytest tests/test_confirm_rate_limit.py tests/test_confirm_customer_rate_limit.py tests/test_settings_bounds.py tests/test_unknown_env_guard.py -q`
Expected: all pass.

- [ ] **Step 9: Format, then run the gate**

Run: `uv run ruff format packages services tests && make ci`
Expected: exit 0.

- [ ] **Step 10: Commit**

```bash
git add services/confirm/rate_limit.py services/confirm/customer_rate_limit.py services/confirm/settings.py services/confirm/main.py packages/postern-core/src/postern_core/env_inventory.py tests/test_confirm_rate_limit.py tests/test_confirm_customer_rate_limit.py tests/test_settings_bounds.py
git commit -m "feat(confirm): rate-limit the QR page routes and POST /scan" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 7: `verification_uri_complete` carries the display handle, and the creator's address is recorded

Spec section 3, first bullet (the page URI is `{device_verification_uri}?d=<display_handle>`, `verification_uri` and `user_code` still returned unchanged) and section 1's `creator_ip` via `pairing_client_ip` and `trusted_proxy_hops`.

**Files:**
- Modify: `packages/postern-core/src/postern_core/auth/device_codes.py` (`DeviceCode.verification_uri_complete`)
- Modify: `services/confirm/device_auth.py` (module docstring's QR paragraph; `device_authorization` docstring and its `create_device_code` call)
- Test: `tests/test_device_grant.py` (`TestDeviceCodeGeneration.test_verification_uri_complete_with_query`, `.test_verification_uri_complete_without_query`; two new tests in `TestDeviceAuthorizationEndpoint`)

- [ ] **Step 1: Write the failing tests**

In `tests/test_device_grant.py`, class `TestDeviceCodeGeneration`, replace `test_verification_uri_complete_with_query` and `test_verification_uri_complete_without_query` with:

```python
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
```

and at the end of class `TestDeviceAuthorizationEndpoint` (after `test_default_scopes_stored`) add:

```python

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
```

- [ ] **Step 2: Run them to verify they fail**

Run: `uv run pytest tests/test_device_grant.py -q -k "verification_uri_complete or complete_uri or creating_address"`
Expected: FAIL. The two `verification_uri_complete` tests with `AssertionError` (the property still appends `user_code=ABCDEF`), the complete-URI test the same way, and `test_the_creating_address_is_recorded_on_the_code` with `assert None == '198.51.100.23'`.

- [ ] **Step 3: Implement**

3a. In `packages/postern-core/src/postern_core/auth/device_codes.py`, replace the `verification_uri_complete` property with:

```python
    @property
    def verification_uri_complete(self) -> str:
        """The pairing page's URI: ``verification_uri`` plus ``d=<display_handle>``.

        RFC 8628 section 3.3.1 lets the complete URI carry the ``user_code``
        "or other information with the same function"; the display handle is
        that other information. It is not the ``user_code`` because a URL
        keyed by a 30-bit code on a public endpoint is an enumeration oracle,
        and it is never the ``device_code``, the one credential ``POST
        /token`` asks for.
        """
        separator = "&" if "?" in self.verification_uri else "?"
        return f"{self.verification_uri}{separator}d={self.display_handle}"
```

3b. In `services/confirm/device_auth.py`'s module docstring, replace

```
QR data encoding: the verification URI with ``user_code`` as a query
parameter (``verification_uri_complete``). The mobile app deep-links to this
URI; the browser shows a QR encoding it.
```

with

```
Two URIs, where there used to be one. ``verification_uri_complete`` is the
PAGE the AI client shows its user: ``verification_uri`` plus ``?d=`` and the
pairing's display handle, 128 random bits that key the page and nothing else.
The QR on that page encodes the APP LINK instead: ``device_app_link_uri`` plus
the ``user_code`` and a two-second rotation token. ``device_code`` is in
neither, because it is the only credential ``POST /token`` asks for, and
anything in a QR is readable over a shoulder or a screen share.
```

3c. In `device_authorization`'s docstring, replace the line `        verification_uri_complete: Full URI with user_code (for deep-linking).` with:

```
        verification_uri_complete: The pairing page, ``verification_uri`` plus
            ``d=`` and the display handle. Never the ``user_code`` and never
            the ``device_code``.
```

3d. In `device_authorization`, the `store.create_device_code(...)` call gains, after `interval=settings.device_poll_interval_seconds,`:

```python
            # RECORDED AND READ BY NOTHING YET. The creator-versus-scanner
            # comparison that would use it is a later spec's; recording it
            # now is what gives that spec something to compare. Under the
            # default of zero trusted hops this is the direct peer, which
            # behind a load balancer is the balancer's address.
            creator_ip=pairing_client_ip(request, settings.trusted_proxy_hops),
```

`pairing_client_ip` is already imported in this module.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `uv run pytest tests/test_device_grant.py -q`
Expected: all pass.

- [ ] **Step 5: Format, then run the gate**

Run: `uv run ruff format packages services tests && make ci`
Expected: exit 0.

- [ ] **Step 6: Commit**

```bash
git add packages/postern-core/src/postern_core/auth/device_codes.py services/confirm/device_auth.py tests/test_device_grant.py
git commit -m "feat(confirm): key verification_uri_complete on the display handle and record the creator" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 8: `POST /approve` by `user_code` only, after a scan, by compare-and-set

Spec section 6 in full, section 7's `/approve` literals and docstring rewrites, section 9, and the removals of section 1 (`update_device_code`, `approve_device_code`, `user_code_attempts`). These have to land in one commit: removing the two store writers breaks `_pair` and `_record_user_code_failure`, which this task rewrites and deletes, and removing `user_code_max_attempts` breaks the budget, which goes with them. About 65 `/approve` request bodies across the test suite move to the new contract here.

Until Task 9 lands `POST /scan`, a pairing can be approved only after a scan made through the store, which is what the test helper below does. Nothing in production creates a scan between this commit and the next.

**Files:**
- Create: `tests/device_grant_helpers.py`
- Modify: `packages/postern-core/src/postern_core/auth/device_codes.py` (module docstring; `DeviceCodeStoreFull` docstring; `DeviceCode` field and docstring; remove `update_device_code` and `approve_device_code` from `DeviceCodeStoreBase`, `InMemoryDeviceCodeStore`, `RedisDeviceCodeStore`; `_set_code` docstring; `_device_code_to_dict`; `_device_code_from_dict`)
- Modify: `services/confirm/device_auth.py` (module docstring; imports; the approval section's comment; new `_USER_CODE_LENGTH`, `_lookup_by_user_code`, `_unpairable_response`, `_approve_refusal_detail`; `approve_callback`; `_withdraw_pairing`; `_pair`; delete `_user_code_matches`, `_record_user_code_failure`; `device_auth_routes` docstring)
- Modify: `services/confirm/audit.py` (`__all__`; new `DETAIL_USER_CODE_NOT_FOUND`, `DETAIL_NOT_SCANNED`, `DETAIL_SCANNED_BY_OTHER`; rewritten `DETAIL_ALREADY_APPROVED`, `DETAIL_DEVICE_CODE_NOT_FOUND`, `DETAIL_USER_CODE_MISMATCH`, `DETAIL_USER_CODE_BUDGET_EXHAUSTED` comments; two sentences of the `PairingAudit` docstring)
- Modify: `services/confirm/settings.py` (remove `user_code_max_attempts` and its `from_env` read; one comment)
- Modify: `services/confirm/customer_rate_limit.py` (one word in `CustomerRateLimit._refuse`'s docstring)
- Modify: `packages/postern-core/src/postern_core/env_inventory.py` (remove one row; the row-count comment)
- Modify: `dev-docs/qr-page-spec.md` (one citation; see Step 13 and the first discrepancy at the end of this plan)
- Test: `tests/test_device_grant.py`, `tests/test_pairing_audit.py`, `tests/test_zt7_confirm_revocation.py`, `tests/test_redis_backed_stores.py`, `tests/test_confirm_auth.py`, `tests/test_confirm_rate_limit.py`, `tests/test_confirm_customer_rate_limit.py`, `tests/test_settings_bounds.py`

- [ ] **Step 1: Create the shared test helper**

Create `tests/device_grant_helpers.py`:

```python
"""Steps the device-grant tests share now that ``POST /approve`` needs a scan.

``POST /approve`` approves only a code the same customer scanned first
(``approve_scanned`` in ``postern_core.auth.device_codes``). Most tests that
approve a pairing are about something after the approval -- the mint, the
audit row, a rate limit -- and not about the scan, so they scan through the
STORE rather than through ``POST /scan``. That keeps them free of the scan's
own ``audit_log`` row, which would change every row count they assert, and
free of the rotation token's two-second clock. The tests that are about the
scan drive ``POST /scan`` over HTTP and use ``qr_for`` for the token.

Not a test module: the name does not start with ``test_``, so pytest does not
collect it.
"""

from __future__ import annotations

import time

from postern_core.auth.device_codes import (
    DeviceCode,
    DeviceCodeStoreBase,
    InMemoryDeviceCodeStore,
    ScanClaim,
)
from starlette.applications import Starlette

from services.confirm.qr_token import slot_at, token_for


def stored_form(user_code: str) -> str:
    """A pairing code as the store keys it: no separator, no spaces, upper case."""
    return user_code.strip().replace("-", "").replace(" ", "").upper()


def device_store_of(app: Starlette) -> DeviceCodeStoreBase:
    """The device-code store the assembled app holds."""
    store: DeviceCodeStoreBase = app.state.device_code_store
    return store


async def stored_code(app: Starlette, user_code: str) -> DeviceCode:
    """The live pairing a displayed or stored-form ``user_code`` names."""
    code = await device_store_of(app).get_by_user_code(stored_form(user_code))
    assert code is not None, f"no live pairing holds user_code {user_code!r}"
    return code


async def scan_in_store(app: Starlette, user_code: str, customer: str) -> DeviceCode:
    """Claim the scan of a pairing for ``customer``, as ``POST /scan`` would.

    A repeat by the same customer is accepted (``ALREADY_MINE``), because
    several tests approve the same pending code more than once.
    """
    code = await stored_code(app, user_code)
    claim = await device_store_of(app).claim_scan(code.device_code, customer)
    assert claim in (ScanClaim.CLAIMED, ScanClaim.ALREADY_MINE), claim
    return code


def qr_for(code: DeviceCode, *, slot_offset: int = 0) -> str:
    """The rotation token the QR would carry now, moved by ``slot_offset`` slots."""
    return token_for(code.qr_secret, code.user_code, slot_at(time.time()) + slot_offset)


def overwrite_in_memory(app: Starlette, code: DeviceCode) -> None:
    """Replace a stored row directly, for tests that bend one out of shape.

    The in-memory backend only: its whole-snapshot writer is gone from the
    store interface on purpose (a snapshot written back undoes a
    compare-and-set), so a test that needs an expired or corrupted row
    reaches into the dict the way several already did before it went.
    """
    store = device_store_of(app)
    assert isinstance(store, InMemoryDeviceCodeStore), type(store).__name__
    store._codes[code.device_code] = code
```

- [ ] **Step 2: Rewrite `tests/test_device_grant.py` to the new contract**

2a. Imports. Add `DeviceCodeStoreBase,` after `DeviceCode,` in the `from postern_core.auth.device_codes import (...)` block, and add `from tests.device_grant_helpers import scan_in_store` on the line directly after `from services.confirm.settings import MIN_DEVICE_CODE_TTL_SECONDS, ConfirmSettings`.

2b. Module docstring. Replace the bullet

```
- In-memory store CRUD (create, get, approve, revoke, update), including the
  ``customer_ref`` / ``user_code_attempts`` fields added for audit findings
  C-01 and C-04.
```

with

```
- In-memory store basics (create, get, revoke), including the
  ``customer_ref`` field added for audit finding C-01. The pairing half of the
  store -- lookups, ``claim_scan``, ``approve_scanned`` -- is in
  ``tests/test_device_code_pairing_store.py``.
```

and the two bullets

```
- The required ``user_code`` pairing-code check (audit finding C-04):
  accepted forms, wrong-code handling, and the attempt budget that revokes
  the device code on the third failure.
- Error cases (invalid_request, invalid_grant, invalid_user_code,
  invalid_subject, slow_down, expired_token, already_approved,
  invalid_state).
```

with

```
- ``POST /approve`` by ``user_code`` only, after a scan: accepted forms of
  the code, the refusal of a code nobody scanned, and the one identical
  ``invalid_grant`` body. ``tests/test_pairing_audit.py`` holds the audit
  ``detail`` each refusal is recorded under.
- Error cases (invalid_request, invalid_grant, invalid_subject, slow_down,
  expired_token, invalid_state).
```

2c. Replace the helper `_approve` with:

```python
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
```

2d. The `_approve` CALL SITES. Transformation rule, applied to every call in the file: insert `app, ` as the first argument, so `_approve(client, X, H...)` becomes `_approve(app, client, X, H...)`, keeping every other argument as it was. The default `scanned_by="cust_7f3a"` is `bearer`'s own default subject, so a call whose bearer names that subject (or whose request is refused before the lookup: every 401 and the `not-a-customer` 403) needs nothing more. Exactly one call names a different subject and expects approval, in `TestAPairingCompletesAtTheConfiguredTtl.test_a_pairing_completes`; it becomes:

```python
            approved = await _approve(
                app, client, device, bearer(key_pair, subject="cust_abc"), scanned_by="cust_abc"
            )
```

The distinct shapes after the rule, each exactly as it must read:

```python
            approve = await _approve(app, client, device, bearer(key_pair, subject="cust_7f3a"))
            resp = await _approve(app, client, pending_code, None)
            resp = await _approve(
                app, client, pending_code, {"Authorization": "Bearer not-a-jwt-at-all"}
            )
            resp = await _approve(app, client, pending_code, bearer(key_pair, expires_in_seconds=-10))
                resp = await _approve(app, client, pending_code, headers)
            resp = await _approve(app, client, device, bearer(key_pair, subject="not-a-customer"))
            resp = await _approve(app, client, device, bearer(key_pair), user_code=bare)
            resp = await _approve(
                app, client, device, bearer(key_pair), user_code=device["user_code"].lower()
            )
            assert (await _approve(app, client, device, bearer(key_pair))).status_code == 200
```

After the edits, `grep -n "_approve(client" tests/test_device_grant.py` prints nothing, and `grep -n -A1 "_approve($" tests/test_device_grant.py` shows `app, client,` on the line after every multi-line call.

2e. `TestInMemoryDeviceCodeStore`: replace `test_new_device_code_defaults_customer_ref_empty_and_attempts_zero`, `test_approve`, `test_double_approve_fails` and `test_approve_nonexistent` with:

```python
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
```

and delete `test_update_device_code` and `test_update_device_code_writes_customer_ref_and_user_code_attempts` (the last two methods of the class) entirely.

2f. Replace the whole class `TestApproveCallback` with:

```python
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
```

2g. `TestFullLifecycle.test_complete_flow`, step 3. Replace

```python
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
```

with

```python
            # Step 3: Mobile app scans (through the store here; POST /scan has
            # its own tests) and approves, with a verified assertion and the
            # pairing code from the QR.
            await scan_in_store(app, device_data["user_code"], "cust_abc")
            resp = await client.post(
                "/approve",
                json={"user_code": device_data["user_code"]},
                headers=bearer(key_pair, subject="cust_abc"),
            )
```

2h. `TestSerialization`: replace `test_customer_ref_and_user_code_attempts_round_trip_through_json`, `test_customer_ref_and_user_code_attempts_round_trip_through_dict` and `test_from_dict_without_the_new_fields_defaults_customer_ref_and_attempts` with:

```python
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
```

2i. `TestApproveCallbackEdgeCases`:
- in `test_extra_body_fields_are_ignored_including_subject_value`, add `await scan_in_store(app, dc["user_code"], "cust_7f3a")` on the line after `dc = dc_resp.json()`, and make the body `json={"user_code": dc["user_code"], "subject_value": "cust_evil", "approval_signature": "sig_xyz"}` (one key per line, as before, without `device_code`);
- replace `test_approve_empty_device_code` with

```python
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
```

- in `test_approve_bearer_with_empty_subject_claim_is_401_not_403`, the body becomes `json={"user_code": "ABCDEF"},`.

2j. `TestCompleteFlow.test_full_device_code_lifecycle`, step 3. Replace

```python
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
```

with

```python
            # 3. Scan and approve via mobile app, with a verified assertion and
            # the pairing code.
            await scan_in_store(app, dc["user_code"], "cust_7f3a")
            approve_resp = await c.post(
                "/approve",
                json={"user_code": dc["user_code"]},
                headers=bearer(key_pair, subject="cust_7f3a"),
            )
```

2k. `TestAuditFindingC01SubjectValueInBodyIsIgnored`: in `test_the_original_exploit_chain_no_longer_completes` the body becomes `json={"user_code": device["user_code"], "subject_value": "cust_victim"},`. In `test_a_bearer_subject_wins_over_a_body_subject_value`, add `await scan_in_store(app, device["user_code"], "cust_attacker")` on the line after `device = await _start_device_grant(client, client_id="cust_victim")`, and the body becomes `json={"user_code": device["user_code"], "subject_value": "cust_victim"},`.

2l. Delete the class `TestUserCodeAttemptBudgetRevokesTheCode` entirely, and delete the section banner `# The floor under POSTERN_USER_CODE_MAX_ATTEMPTS.` with its two rule lines and the whole class `TestTheUserCodeAttemptBudgetFloor` beneath it, so the rule above that banner becomes the rule above `# One approved device code buys one read token.`.

2m. `TestApproveCallbackHandlerFailsClosedWithoutMiddleware.test_handler_called_directly_with_seeded_assertion_reaches_body_validation`: the body becomes `body = json.dumps({"user_code": ""}).encode()`.

2n. `TestConsumingADeviceCodeInTheStore`'s docstring: ``` A separate contract from ``approve_device_code``'s and the same shape: ``` becomes ``` A separate contract from ``approve_scanned``'s and the same shape: ```.

- [ ] **Step 3: Rewrite `tests/test_pairing_audit.py` to the new contract**

3a. Imports: the `from services.confirm.audit import (...)` block gains `DETAIL_NOT_SCANNED,` (after `DETAIL_INVALID_SUBJECT,`), `DETAIL_SCANNED_BY_OTHER,` (after `DETAIL_REVOKED,`) and `DETAIL_USER_CODE_NOT_FOUND,` (after `DETAIL_USER_CODE_MISMATCH,`), and add `from tests.device_grant_helpers import overwrite_in_memory, scan_in_store` directly after `from services.confirm.settings import ConfirmSettings`.

3b. Replace the helper `issue` with:

```python
async def issue(
    app: Starlette, client_id: str = BROWSER_CLIENT, *, scanned_by: str | None = CUSTOMER
) -> DeviceCode:
    """One device code, created through the store the app actually holds.

    Scanned by ``scanned_by`` through the store, as ``POST /scan`` would have,
    because ``POST /approve`` approves only a code the approving customer
    scanned; ``None`` leaves it unscanned. Through the store and not over
    HTTP so the scan's own row does not join the ones these tests count.
    """
    store: DeviceCodeStoreBase = app.state.device_code_store
    code = await store.create_device_code(
        client_id=client_id,
        scopes="accounts:read",
        verification_uri="https://auth.test.invalid/verify",
    )
    if scanned_by is not None:
        await scan_in_store(app, code.user_code, scanned_by)
    return code
```

3c. Transformation rule for the bodies: every `{"device_code": code.device_code, "user_code": code.user_code_display},` becomes `{"user_code": code.user_code_display},`. `issue` now scans for `CUSTOMER` by default, so no call site needs a scan of its own. That is nine sites: `test_a_successful_pairing_writes_one_row`, `test_the_row_is_one_and_not_the_read_paths_pair`, `test_the_row_names_no_raw_device_code`, `test_the_row_records_the_address_the_request_came_from`, `test_a_revoked_customer_is_recorded_with_the_challenge_paths_literal`, `test_a_pairing_that_cannot_be_audited_does_not_stand`, `paired`, and the two in `test_a_second_approval_of_an_approved_code_is_recorded`, which 3d replaces anyway.

3d. Replace everything from `async def test_an_unknown_device_code_is_recorded(` up to (not including) `async def test_a_revoked_customer_is_recorded_with_the_challenge_paths_literal(` -- that is, `test_an_unknown_device_code_is_recorded`, `test_a_wrong_pairing_code_is_recorded`, `test_exhausting_the_pairing_code_budget_is_a_different_detail` and `test_a_second_approval_of_an_approved_code_is_recorded` -- with:

```python
async def test_an_unknown_user_code_is_recorded(
    app: Starlette, clean: Database, key_pair: RSAKeyPair
) -> None:
    """The enumeration signal, and the branch with no pairing to name.

    A ``user_code`` is 30 bits, so guessing one is cheap, and the row is the
    only place the attempts are countable: N rows of ``user_code_not_found``
    under one ``customer_ref`` is somebody walking the code space. The row
    names no device code, because the guess named none.
    """
    resp = await approve(app, {"user_code": "ZZZ-ZZZ"}, bearer(key_pair))
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_grant"

    row = await one_row(clean)
    assert row.outcome == OUTCOME_RAISED
    assert row.detail == DETAIL_USER_CODE_NOT_FOUND
    assert row.customer_ref == CUSTOMER
    assert "device_code_handle" not in row.arguments
    assert "paired_client_id" not in row.arguments


async def test_an_unscanned_code_is_recorded_as_not_scanned(
    app: Starlette, clean: Database, key_pair: RSAKeyPair
) -> None:
    """An app skipping ``POST /scan``, or something guessing codes that
    happened to hit a live one. Either way nothing is approved."""
    code = await issue(app, scanned_by=None)

    resp = await approve(app, {"user_code": code.user_code_display}, bearer(key_pair))
    assert resp.status_code == 400

    row = await one_row(clean)
    assert row.detail == DETAIL_NOT_SCANNED
    assert row.arguments["device_code_handle"] == handle_of(code.device_code)
    assert row.arguments["paired_client_id"] == BROWSER_CLIENT
    stored = await unwrap(app.state.device_code_store, code.device_code)
    assert stored.approved is False


async def test_a_code_another_customer_scanned_is_recorded_as_scanned_by_other(
    app: Starlette, clean: Database, key_pair: RSAKeyPair
) -> None:
    """Scanned by A, approved by B: refused, and the row says so under B."""
    code = await issue(app, scanned_by="cust_a11ce")

    resp = await approve(app, {"user_code": code.user_code_display}, bearer(key_pair))
    assert resp.status_code == 400

    row = await one_row(clean)
    assert row.detail == DETAIL_SCANNED_BY_OTHER
    assert row.customer_ref == CUSTOMER
    stored = await unwrap(app.state.device_code_store, code.device_code)
    assert stored.approved is False
    assert stored.scanned_by == "cust_a11ce"


async def test_a_repeat_approval_by_the_scanner_is_recorded_as_already_approved(
    app: Starlette, clean: Database, key_pair: RSAKeyPair
) -> None:
    """Normally a retried request. Both rows name the same pairing."""
    code = await issue(app)
    first = await approve(app, {"user_code": code.user_code_display}, bearer(key_pair))
    assert first.status_code == 200

    second = await approve(app, {"user_code": code.user_code_display}, bearer(key_pair))
    assert second.status_code == 400

    written = await rows(clean)
    assert [r.outcome for r in written] == [OUTCOME_RETURNED, OUTCOME_RAISED]
    assert written[1].detail == DETAIL_ALREADY_APPROVED
    assert (
        written[0].arguments["device_code_handle"] == (written[1].arguments["device_code_handle"])
    ), "both rows name the same pairing, which is what makes the pair readable"


@pytest.mark.parametrize("vanishes_by", ["revocation", "expiry"])
async def test_a_row_gone_between_the_lookup_and_the_refusal_is_user_code_not_found(
    app: Starlette,
    clean: Database,
    key_pair: RSAKeyPair,
    monkeypatch: pytest.MonkeyPatch,
    vanishes_by: str,
) -> None:
    """Section 6's first label: gone or expired by the time it is re-read.

    The window is forced by replacing ``approve_scanned`` with one that makes
    the row vanish and then refuses, which is the order a real race would
    produce: the lookup found a live row, the compare-and-set did not approve
    it, and the re-read finds nothing live.
    """
    store: DeviceCodeStoreBase = app.state.device_code_store
    code = await issue(app)

    async def vanish_then_refuse(device_code: str, customer_ref: str) -> bool:
        if vanishes_by == "revocation":
            await store.revoke_device_code(device_code)
        else:
            stored = await unwrap(store, device_code)
            past = datetime.now(UTC) - timedelta(seconds=1)
            overwrite_in_memory(app, replace(stored, expires_at=past))
        return False

    monkeypatch.setattr(store, "approve_scanned", vanish_then_refuse)

    resp = await approve(app, {"user_code": code.user_code_display}, bearer(key_pair))
    assert resp.status_code == 400

    row = await one_row(clean)
    assert row.detail == DETAIL_USER_CODE_NOT_FOUND
    assert row.arguments["device_code_handle"] == handle_of(code.device_code)


async def test_every_refusal_about_a_pairing_answers_one_identical_body(
    app: Starlette, clean: Database, key_pair: RSAKeyPair
) -> None:
    """Unknown, unscanned, scanned by another, already approved: four
    different rows and one response, so the response is not an oracle."""
    unscanned = await issue(app, scanned_by=None)
    someone_elses = await issue(app, scanned_by="cust_a11ce")
    approved = await issue(app)
    assert (
        await approve(app, {"user_code": approved.user_code_display}, bearer(key_pair))
    ).status_code == 200
    await _wipe(clean)

    bodies = []
    for user_code in (
        "ZZZ-ZZZ",
        unscanned.user_code_display,
        someone_elses.user_code_display,
        approved.user_code_display,
    ):
        resp = await approve(app, {"user_code": user_code}, bearer(key_pair))
        assert resp.status_code == 400
        bodies.append(resp.json())

    assert all(body == bodies[0] for body in bodies), bodies
    assert [r.detail for r in await rows(clean)] == [
        DETAIL_USER_CODE_NOT_FOUND,
        DETAIL_NOT_SCANNED,
        DETAIL_SCANNED_BY_OTHER,
        DETAIL_ALREADY_APPROVED,
    ]


def test_the_retired_literals_stay_defined_for_the_rows_that_carry_them() -> None:
    """``audit_log`` is append-only, so rows carrying these exist and nothing
    in the tree may stop naming them, though nothing writes them any more."""
    assert DETAIL_DEVICE_CODE_NOT_FOUND == "device_code_not_found"
    assert DETAIL_USER_CODE_MISMATCH == "user_code_mismatch"
    assert DETAIL_USER_CODE_BUDGET_EXHAUSTED == "user_code_budget_exhausted"
    assert DETAIL_USER_CODE_NOT_FOUND == "user_code_not_found"
    assert DETAIL_NOT_SCANNED == "not_scanned"
    assert DETAIL_SCANNED_BY_OTHER == "scanned_by_other"
```

3e. In `test_a_subject_that_is_not_a_customer_reference_is_recorded_as_an_absence`, the body becomes `{"user_code": "ABC-DEF"},`. In `test_a_request_with_no_assertion_writes_no_row`, the call becomes `resp = await approve(app, {"user_code": "ABC-DEF"})`.

3f. Replace the parameter list of `test_a_malformed_request_writes_no_row` with:

```python
@pytest.mark.parametrize(
    "body",
    [
        pytest.param([1, 2, 3], id="a JSON array rather than an object"),
        pytest.param({}, id="no user_code"),
        pytest.param({"user_code": ""}, id="user_code is empty"),
        pytest.param({"user_code": 123}, id="user_code is a number"),
        pytest.param({"user_code": ["x"]}, id="user_code is a list"),
        pytest.param(
            dict(device_code="abc", user_code="ABC-DEF"),
            id="the removed device_code is still sent",
        ),
    ],
)
```

The last case is written with `dict(...)` on purpose: it is the one body in the suite that must still carry `device_code`, and the proof in Step 12 looks for dict literals.

3g. The two `update_device_code` calls become `overwrite_in_memory` calls. In `test_an_expired_device_code_writes_nothing`:

```python
    overwrite_in_memory(
        app,
        replace(
            await unwrap(store, code.device_code),
            expires_at=datetime.now(UTC) - timedelta(seconds=1),
        ),
    )
```

and in `test_a_stored_identity_that_is_not_a_customer_reference_is_recorded`:

```python
    overwrite_in_memory(
        app,
        replace(await unwrap(store, code.device_code), customer_ref="4111111111111111"),
    )
```

- [ ] **Step 4: Rewrite `tests/test_zt7_confirm_revocation.py`**

Add `from tests.device_grant_helpers import scan_in_store` directly before `from tests.fixtures.append_only_bypass import (`. Replace the helper `paired` with:

```python
async def paired(app: Starlette, key_pair: RSAKeyPair, customer: str) -> str:
    """Drive a real device pairing to the point where ``/token`` would mint.

    Every step but the scan is the production path: the browser opens the
    grant, the banking app approves it with a verified assertion, and the
    customer lands on the device code from that assertion's ``sub`` and from
    nowhere else. The scan is claimed through the store, which is where
    ``POST /scan`` would have claimed it, so this file's audit counts stay
    about revocation. Returns the ``device_code`` the browser would poll with.
    """
    opened = await post_form(app, "/device_authorization", {"client_id": CLIENT})
    assert opened.status_code == 200, opened.text
    device_code = opened.json()["device_code"]
    user_code = opened.json()["user_code"]
    await scan_in_store(app, user_code, customer)

    approved = await post_json(
        app,
        "/approve",
        {"user_code": user_code},
        bearer(key_pair, customer),
    )
    assert approved.status_code == 200, approved.text
    return str(device_code)
```

In `test_a_revoked_customer_cannot_approve_a_device_pairing_at_all`, the `post_json` body becomes `{"user_code": user_code},` (no scan: the revocation refuses before the lookup).

- [ ] **Step 5: Rewrite `tests/test_redis_backed_stores.py`**

- Delete `test_an_update_rescores_the_index_member_instead_of_adding_a_second` and `test_an_update_that_shortens_a_life_moves_the_member_earlier`. Both pinned `update_device_code` re-scoring the index; nothing re-scores it now, because nothing but creation writes a row with a new expiry.
- In `test_a_code_whose_expiry_has_already_passed_is_never_written_or_indexed`, `await store.update_device_code(stale.device_code, stale)` becomes `await store._set_code(stale.device_code, stale)`; that test is about `_set_code`, as its docstring already says.
- Replace `test_a_device_code_round_trips_every_field_to_a_second_connection` and `test_an_approval_crosses_to_a_second_connection_and_cannot_be_repeated` with:

```python
async def test_a_device_code_round_trips_every_field_to_a_second_connection(
    stores: RedisStores,
) -> None:
    """Two stores, two pools, one server: what a second replica reads back.

    ``expires_at`` crosses as a POSIX float and returns as a ``datetime``,
    and ``customer_ref`` is the field audit finding C-01 separated from
    ``client_id``, so a round trip that lost it would re-open it. The identity
    is written the only way this store writes one now, through a scan and an
    approval, each a compare-and-set.
    """
    writer = stores.device_codes()
    reader = stores.device_codes()
    code = await _create(writer, expires_in=600)

    assert await writer.claim_scan(code.device_code, "cust_7f3a") is ScanClaim.CLAIMED
    assert await writer.approve_scanned(code.device_code, "cust_7f3a") is True

    seen = await reader.get_device_code(code.device_code)

    assert seen is not None
    assert seen.device_code == code.device_code
    assert seen.user_code == code.user_code
    assert seen.verification_uri == VERIFY_URI
    assert seen.client_id == "vendor-a"
    assert seen.scopes == "accounts:read"
    assert seen.customer_ref == "cust_7f3a"
    assert seen.scanned_by == "cust_7f3a"
    assert seen.expires_at.timestamp() == pytest.approx(code.expires_at.timestamp(), abs=0.001)
    assert isinstance(await reader._redis.get(reader._key(code.device_code)), str), (
        "decode_responses=True comes from RedisDeviceCodeStore.__init__, not from a fixture"
    )


async def test_an_approval_crosses_to_a_second_connection_and_cannot_be_repeated(
    stores: RedisStores,
) -> None:
    """``approve_scanned`` is a WATCH/MULTI round trip, read back elsewhere."""
    writer = stores.device_codes()
    reader = stores.device_codes()
    code = await _create(writer)
    await writer.claim_scan(code.device_code, "cust_7f3a")

    assert await writer.approve_scanned(code.device_code, "cust_7f3a") is True

    seen = await reader.get_device_code(code.device_code)
    assert seen is not None
    assert seen.approved is True
    assert seen.approved_at is not None
    assert await reader.approve_scanned(code.device_code, "cust_7f3a") is False, (
        "a second approval is refused on the value the server holds"
    )
```

- [ ] **Step 6: Rewrite the three limiter and auth test files**

6a. `tests/test_confirm_auth.py`, `test_a_valid_assertion_reaches_the_handler_with_its_body_intact`: the body becomes `json={"user_code": "ABC-DEF"},`. It still answers `invalid_grant`, now from the `user_code` lookup.

6b. `tests/test_confirm_rate_limit.py`: add `from tests.device_grant_helpers import scan_in_store` directly before `from tests.test_device_grant import AUDIENCE, ISSUER, bearer`. In each of `test_a_legitimate_pairing_completes_under_the_limit`, `test_a_legitimate_pairing_still_completes_while_another_bucket_floods` and `test_an_approved_code_is_bounded_by_being_spent_and_not_by_a_limit`, insert `await scan_in_store(app, device["user_code"], "cust_7f3a")` on the line before the `/approve` post, and make that post's body `json={"user_code": device["user_code"]},`. The scan goes through the store, so it spends nothing from the limits these tests count.

6c. `tests/test_confirm_customer_rate_limit.py`: add `from tests.device_grant_helpers import scan_in_store` directly before `from tests.test_device_grant import AUDIENCE, ISSUER, bearer`. Replace the helper `_pair` with:

```python
async def _pair(app: Starlette, client: httpx2.AsyncClient, scanned_by: str = CUSTOMER) -> str:
    """Start a device grant, scan it in the store as ``scanned_by``, and
    return its ``user_code``.

    The pairing is real, so `test_a_legitimate_approval_completes_under_the_ceiling`
    below asserts a 200 from the handler rather than "not a 429", which a
    limiter that let everything through would also satisfy. The scan goes
    through the store rather than ``POST /scan``, so it spends nothing from
    either limiter these tests count.
    """
    response = await client.post("/device_authorization", json={"client_id": "browser-1"})
    assert response.status_code == 200, response.text
    user_code = str(response.json()["user_code"])
    await scan_in_store(app, user_code, scanned_by)
    return user_code
```

Then apply two transformation rules. Rule 1: `device_code, user_code = await _pair(X)` becomes `user_code = await _pair(app, X)`, and the body that follows, `{"device_code": device_code, "user_code": user_code}`, becomes `{"user_code": user_code}` (three sites: `test_two_customers_from_one_address_do_not_share_a_budget`, `test_one_customer_from_two_addresses_shares_one_budget`, `test_a_legitimate_approval_completes_under_the_ceiling`). Rule 2: every `{"device_code": "x", "user_code": "y"}` becomes `{"user_code": "y"}` (five sites across `test_an_address_refusal_never_reaches_the_assertion_verifier`, `test_the_outer_ceiling_still_refuses_before_the_customer_one` and `test_the_two_ceilings_answer_different_bodies_from_one_app`). Those tests assert on the limiters, which answer before the handler, so the handler's new answer to an unknown code changes none of their assertions.

- [ ] **Step 7: Move `tests/test_settings_bounds.py`**

Delete the `Bounded("POSTERN_USER_CODE_MAX_ATTEMPTS", "user_code_max_attempts", ...)` row from `BOUNDED`. In `test_the_two_inventories_are_the_whole_tree` the docstring becomes `"""72 variables, 27 read directly and 45 through a reader, disjoint."""` and `KNOWN_ENV` 73 becomes 72; in `test_the_counts_the_docstrings_quote`, `KNOWN_ENV` 73 becomes 72, `BOUNDED_NAMES` 39 becomes 38, the four-way union 46 becomes 45, and `names_read_by("confirm")` 57 becomes 56.

- [ ] **Step 8: Run the tests to verify they fail**

Run: `uv run pytest tests/test_device_grant.py tests/test_pairing_audit.py -q`
Expected: collection error in `tests/test_pairing_audit.py`, `ImportError: cannot import name 'DETAIL_NOT_SCANNED' from 'services.confirm.audit'`; then, once that is past, `test_the_store_offers_no_whole_snapshot_write` failing on `assert not hasattr(...)`, the approvals answering `400 invalid_request` with `"device_code and user_code are required"`, and `test_a_body_still_carrying_device_code_is_refused_loudly` answering 200 instead of 400.

- [ ] **Step 9: Implement the store half, in `packages/postern-core/src/postern_core/auth/device_codes.py`**

9a. Module docstring. Replace the numbered flow and the two bullets under it (from `1. Browser calls ``/device_authorization```` down to `  both codes.`) with:

```
1. Browser calls ``/device_authorization`` and gets a device code, a
   user-visible pairing code (6 chars) and ``verification_uri_complete``,
   the pairing page keyed by the code's display handle.
2. The page shows the pairing code and a QR that encodes the operator's app
   link with the ``user_code`` and a rotation token; ``device_code`` is in
   neither.
3. The bank app scans it and calls ``POST /scan``, which records the first
   scanning customer by compare-and-set (``claim_scan``).
4. The user compares the pairing codes and completes identity verification;
   the app calls ``POST /approve`` with the ``user_code``, which approves by
   compare-and-set only for the customer who scanned (``approve_scanned``).
5. After approval, the browser polls ``/token`` with
   ``grant_type=device_code`` to receive a read token.

The pairing code (``user_code``) carries the anti-phishing control for
A2 (QR relay), and it is worth being precise about which half lives where,
because the two halves are not interchangeable:

- The HUMAN half is the control against a relayed QR. The user compares the
  code their own trusted screen shows against the code the app shows, and
  refuses if they differ. That comparison happens on the operator's app
  pairing screen, which is not in this repository and is still an open
  question (handoff §10.10). Nothing here can perform it or verify that it
  happened.
- The SERVER half is the scan. A code can be approved only by the customer
  whose app scanned it with a genuine, current rotation token, and a second
  customer's scan of an unexchanged code ends the pairing. Guessing a
  ``user_code`` at ``POST /approve`` therefore approves nothing the same
  customer did not scan first. It does NOT detect a relay, because a
  relaying attacker who shows the victim the attacker's own page holds a
  genuine QR; ``dev-docs/qr-page-spec.md`` says so in "What this does not
  fix".
```

9b. `DeviceCodeStoreFull`'s docstring. Replace its first paragraph, the six lines beginning `REFUSING IS THE DECISION, and the alternative was evicting the oldest` and ending `on", because "only one of them destroys a session in flight".`, with:

```
    REFUSING IS THE DECISION, and the alternative was evicting the oldest
    code. Eviction would let an unauthenticated caller end another customer's
    pairing in flight simply by filling the store, and nothing else on this
    path lets a party without an assertion do that.
```

9c. `DeviceCode`: delete the docstring line `        user_code_attempts: Failed ``user_code`` comparisons at ``/approve``.` and the field `    user_code_attempts: int = 0`.

9d. `DeviceCodeStoreBase`: delete the abstract `approve_device_code` (decorator, signature and one-line docstring), and replace the abstract `update_device_code` (decorator, signature and docstring) with this comment:

```python
    # NO WHOLE-SNAPSHOT WRITE, deliberately, since 2026-09-30. This class
    # offered ``update_device_code`` and ``approve_device_code``, and each
    # wrote a whole row back: a snapshot read before a concurrent
    # ``claim_scan`` or ``approve_scanned`` and written after it silently
    # undoes that compare-and-set, and neither touched the two secondary
    # keys. Every write to an existing code now goes through one of the three
    # compare-and-set methods above or through ``revoke_device_code``.
```

9e. `InMemoryDeviceCodeStore`: delete `approve_device_code` and `update_device_code`. `RedisDeviceCodeStore`: delete `approve_device_code` and `update_device_code`.

9f. `RedisDeviceCodeStore._set_code`'s docstring. Replace its first paragraph after the summary line,

```
        ``ZADD`` on every write and not only on creation, so an update
        re-scores rather than leaving the index holding an older expiry than
        the value it points at. Both are skipped when the TTL has already
        passed, which is the existing behaviour for the value and keeps the
        index from gaining a member that is due the moment it lands.
```

with

```
        Called by ``create_device_code`` only. Every later write to a code --
        the scan claim, the approval, the exchange -- is a ``WATCH``/``MULTI``
        transaction with ``KEEPTTL``, because none of them moves the expiry
        and none may be undone by a stale snapshot. Both writes here are
        skipped when the TTL has already passed, which keeps the index from
        gaining a member that is due the moment it lands.
```

and in the `NO GUARD IS RAISED HERE` paragraph replace its first eleven lines, from `NO GUARD IS RAISED HERE, deliberately. This method has three callers` through `accepts, which does not end the disagreement between them, it only`, with:

```
        NO GUARD IS RAISED HERE, deliberately. Until 2026-09-30 this method
        had two more callers, the whole-snapshot writers the compare-and-set
        methods replaced, and for them a zero TTL was an ordinary race rather
        than a caller asking for a lifetime that cannot be represented. With
        ``create_device_code`` the only caller, raising here would be raising
        there, and it would make this backend refuse a lifetime
        `InMemoryDeviceCodeStore` accepts, which does not end the
        disagreement between them, it only
```

(the paragraph continues unchanged with `moves it from the outcome to the control flow and puts it in`).

9g. `_device_code_to_dict`: delete `        "user_code_attempts": dc.user_code_attempts,`. `_device_code_from_dict`: replace `        user_code_attempts=int(data.get("user_code_attempts", 0)),` with

```python
        # A ``user_code_attempts`` key on a record the previous release wrote
        # is ignored: the per-code attempt budget it counted was removed when
        # the pairing code became the lookup key, where it means nothing.
```

- [ ] **Step 10: Implement the audit literals, in `services/confirm/audit.py`**

10a. `__all__` gains `"DETAIL_NOT_SCANNED",` (after `"DETAIL_MISSING_SIGNATURE",`), `"DETAIL_SCANNED_BY_OTHER",` (after `"DETAIL_REVOKED",`) and `"DETAIL_USER_CODE_NOT_FOUND",` (after `"DETAIL_USER_CODE_MISMATCH",`).

10b. Replace the two-line comment and the assignment of `DETAIL_DEVICE_CODE_NOT_FOUND` with:

```python
#: A ``device_code`` at ``POST /approve`` that named nothing, the endpoint's
#: enumeration signal while the app sent a ``device_code``.
#:
#: HISTORICAL SINCE 2026-09-30, and kept for the rows that carry it.
#: ``POST /approve`` takes a ``user_code`` now and writes
#: ``DETAIL_USER_CODE_NOT_FOUND`` for its miss, and ``POST /token``'s unknown
#: code writes no row at all, so no code in this repository writes this literal
#: any more. ``audit_log`` is append-only, so deleting the name would leave
#: those rows carrying a value nothing in the tree names.
DETAIL_DEVICE_CODE_NOT_FOUND = "device_code_not_found"
#: A ``user_code`` that names no live pairing: unknown, or expired, at
#: ``POST /scan`` or ``POST /approve``, including a row revoked or expired
#: between ``POST /approve``'s lookup and its re-read after a refused
#: ``approve_scanned``.
#:
#: NEW RATHER THAN A REUSE OF ``DETAIL_DEVICE_CODE_NOT_FOUND``, because the two
#: guesses are not the same size. A ``device_code`` miss is a guess at 256 bits
#: of ``secrets`` entropy; a ``user_code`` miss is a guess at 30 bits, which is
#: exactly the enumeration signal keying on the pairing code opens. One literal
#: for both would mix the cheap guess into the expensive one's history.
DETAIL_USER_CODE_NOT_FOUND = "user_code_not_found"
#: ``POST /approve`` for a code nobody has scanned. Approval requires the
#: approving customer to have scanned first, so this is either an app skipping
#: ``POST /scan`` or something guessing ``user_code`` values.
DETAIL_NOT_SCANNED = "not_scanned"
#: ``POST /approve`` for a code another customer scanned. The response is the
#: same ``invalid_grant`` every other refusal gets; this literal is where an
#: operator sees one customer trying to approve a pairing another one holds.
DETAIL_SCANNED_BY_OTHER = "scanned_by_other"
```

10c. Replace the comments and assignments of `DETAIL_ALREADY_APPROVED`, `DETAIL_USER_CODE_MISMATCH` and `DETAIL_USER_CODE_BUDGET_EXHAUSTED` with:

```python
#: A repeat approval by the customer who scanned the code, normally a retried
#: request, at ``POST /approve`` when the code is already approved.
#:
#: REWRITTEN ON 2026-09-30, because the rationale it carried stopped being
#: possible. It used to be a caller holding an assertion of their own swapping
#: ``customer_ref`` to themselves in the window before the browser polls
#: ``POST /token``. ``approve_scanned`` now approves only for the customer in
#: ``scanned_by``, in one compare-and-set, so nobody else can reach an
#: approved code's identity at all; another customer's attempt is
#: ``DETAIL_SCANNED_BY_OTHER``.
DETAIL_ALREADY_APPROVED = "already_approved"
#: A wrong pairing code with attempts left, from the per-code attempt budget.
#:
#: HISTORICAL SINCE 2026-09-30, like the literal below: the budget went when
#: the pairing code became the lookup key, where a per-code budget means
#: nothing, and nothing writes either literal any more. Both stay defined
#: because ``audit_log`` is append-only and rows carrying them exist.
DETAIL_USER_CODE_MISMATCH = "user_code_mismatch"
#: The wrong pairing code that spent the last attempt and revoked the device
#: code. Historical since 2026-09-30; see the literal above.
DETAIL_USER_CODE_BUDGET_EXHAUSTED = "user_code_budget_exhausted"
```

10d. In `PairingAudit`'s docstring, replace

```
    where the caller IS authenticated: a body that is not a JSON object, a
    missing ``device_code``, a ``user_code`` that arrives as a list.
```

with

```
    where the caller IS authenticated: a body that is not a JSON object, a
    missing ``user_code``, a ``user_code`` that arrives as a list, a body
    still carrying the removed ``device_code``.
```

and

```
    What the rule ADMITS, on each endpoint. At ``POST /approve``: a revoked
    customer, a subject that is not a customer reference, a device code naming
    nothing, a code already approved, and both halves of a wrong pairing code.
```

with

```
    What the rule ADMITS, on each endpoint. At ``POST /approve``: a revoked
    customer, a subject that is not a customer reference, a ``user_code``
    naming no live pairing, a code nobody scanned, a code another customer
    scanned, and a code already approved.
```

- [ ] **Step 11: Implement the handler, in `services/confirm/device_auth.py`**

11a. Module docstring. Replace

```
Pairing code (``user_code``): 6 uppercase alphanumeric chars, displayed as
XXX-XXX on both surfaces. ``POST /approve`` REQUIRES it and compares it, in
constant time, against the code stored for that device code
(``postern_core.auth.device_codes`` records which half of the A2 control that
is and which half only the operator's app can perform).
```

with

```
Pairing code (``user_code``): 6 uppercase alphanumeric chars, displayed as
XXX-XXX on both surfaces. ``POST /approve`` takes it and nothing else that
names the pairing, looks the pairing up by it, and approves only if the same
customer scanned it first (``postern_core.auth.device_codes`` records which
half of the A2 control that is and which half only the operator's app can
perform).
```

11b. Imports: delete `import hmac`. In the `from services.confirm.audit import (...)` block delete `DETAIL_DEVICE_CODE_NOT_FOUND,`, `DETAIL_USER_CODE_BUDGET_EXHAUSTED,` and `DETAIL_USER_CODE_MISMATCH,`, and add `DETAIL_NOT_SCANNED,` (after `DETAIL_INVALID_SUBJECT,`), `DETAIL_SCANNED_BY_OTHER,` (after `DETAIL_REVOKED,`) and `DETAIL_USER_CODE_NOT_FOUND,` (after `DETAIL_STORED_IDENTITY_MALFORMED,`).

11c. The comment block under `# Approval callback — POST /approve.`: replace

```
# Called by the operator's banking app after the user completes identity
# verification and confirms the device pairing. It marks the device code
# approved so the browser can exchange it for tokens.
#
# The app sends:
#   device_code — the opaque device code, from the scanned QR.
#   user_code   — the pairing code, from the same QR. REQUIRED and compared.
#
```

with

```
# Called by the operator's banking app after the user has scanned the QR
# (``POST /scan``), compared the pairing codes and completed identity
# verification. It marks the device code approved so the browser can exchange
# it for a read token.
#
# The app sends ``user_code`` and nothing else that names the pairing.
# ``device_code`` is refused if present: it is the only credential
# ``POST /token`` asks for, it is never in the QR, and the app never learns
# it, so a body carrying one is an app on the old contract and must fail
# loudly rather than be half-honoured.
#
```

11d. Directly after `_normalize_user_code` and before `@dataclasses.dataclass(frozen=True, slots=True)` / `class _Pairing`, add:

```python
@@SNIP|t8|services/confirm/device_auth.py|#: The length of a stored pairing code. A presented value that normalises to|@dataclasses.dataclass(frozen=True, slots=True)@@
```

11e. `approve_callback`'s docstring. Replace

```
    Request body:
        device_code: The opaque device code (required).
        user_code: The pairing code shown in the QR, ``XXX-XXX`` or bare
            (required -- audit finding C-04).

    Response (200): ``{"status": "approved"}``
    Response (400): device code unknown, already approved, or pairing code
        wrong.
```

with

```
    Request body:
        user_code: The pairing code the app read from the scanned QR,
            ``XXX-XXX`` or bare. A body that also carries ``device_code`` is
            refused.

    Response (200): ``{"status": "approved"}``
    Response (400): ``invalid_request`` for a malformed body or one still
        carrying ``device_code``, and the one ``invalid_grant`` body of
        ``_unpairable_response`` for every refusal that concerns a pairing.
```

11f. In `approve_callback`'s body, the call becomes `outcome = await _pair(request, audit, store=store, subject=subject)`, and the comment's last paragraph under it,

```
        # Nothing was approved on any path that raises -- the store write is
        # the last statement of `_pair` and an exception from it leaves the
        # code unapproved -- so there is nothing to withdraw here.
```

becomes

```
        # Nothing was approved on any path that raises: the only write in
        # `_pair` is `approve_scanned`, a compare-and-set that either commits
        # and returns or raises having written nothing, and nothing after a
        # successful one can raise. There is nothing to withdraw here.
```

11g. `_withdraw_pairing`'s docstring. Replace its first paragraph with:

```
    Revocation rather than an in-place undo, because the recovery the
    customer needs is a fresh QR anyway, and a fresh QR is what re-anchors the
    human pairing-code comparison that is the real A2 control. Rewriting
    ``approved`` or ``scanned_by`` back would leave the same ``device_code``
    live, and a racing poll or a racing scan could still find it in the state
    the failed request could not record.
```

11h. `_pair`. Delete the parameter `settings: ConfirmSettings,` from its signature. Add a second paragraph to its docstring, after the existing one:

```
    THE APPROVAL IS A COMPARE-AND-SET. Until 2026-09-30 this read the code,
    checked ``approved``, and wrote the whole snapshot back with a plain
    ``SETEX``, so two replicas could both pass the check and the last writer's
    ``customer_ref`` won. ``approve_scanned`` settles it inside the store: it
    approves only a code that is unexpired, unapproved and scanned by this
    same customer, and answers ``True`` to one caller. What this function
    reads after a refusal labels the audit row and decides nothing.
```

Keep the `CustomerRef` block, the ZT-7 block and the body parse (`try: body = await request.json()` and the `isinstance(body, dict)` check) unchanged. Replace everything after them -- from `    device_code_value = body.get("device_code", "")` down to the end of `_record_user_code_failure`, which removes `_user_code_matches` and `_record_user_code_failure` -- with:

```python
    # THE OLD CONTRACT IS REFUSED, NOT IGNORED. An app still sending
    # ``device_code`` was built against a QR that carried it, and ignoring the
    # field would let that app half-work until the day it did not. A 400 it
    # cannot mistake for a pairing refusal is the loud failure.
    if "device_code" in body:
        return _Pairing(
            _error(400, "invalid_request", "device_code is not accepted; send user_code only"),
            recorded=False,
        )

    user_code_value = body.get("user_code", "")

    # `isinstance`, not just truthiness. JSON gives a caller ints, lists and
    # objects as easily as strings, and `{"user_code": 123}` would otherwise
    # reach `_normalize_user_code` and raise `AttributeError` -- a 500 from an
    # endpoint that should answer 400. On an authenticated write path a 500 is
    # also the shape that gets "fixed" by relaxing something.
    if not isinstance(user_code_value, str):
        return _Pairing(
            _error(400, "invalid_request", "user_code must be a string"), recorded=False
        )
    if not user_code_value:
        return _Pairing(_error(400, "invalid_request", "user_code is required"), recorded=False)

    # THE EXITS ABOVE ARE THE RULE'S OTHER HALF. Each is answered by looking
    # at the request and consulting nothing, each names no pairing, and a row
    # for each would hand a caller holding one valid assertion an INSERT per
    # malformed body. `PairingAudit` carries the rule and what excluding them
    # costs.

    existing = await _lookup_by_user_code(store, user_code_value)
    if existing is None:
        return _Pairing(_unpairable_response(), DETAIL_USER_CODE_NOT_FOUND)

    # From here the request names a pairing, so every exit below is a
    # conclusion about one and every exit below is recorded. WHICH CLIENT IS
    # BEING PAIRED is the other half of the name: the browser supplied it,
    # unauthenticated, at `/device_authorization`, and it is never an
    # identity, but on every refused path below it exists nowhere else once
    # the code expires.
    audit.names(device_code=existing.device_code, paired_client_id=existing.client_id)

    if await store.approve_scanned(existing.device_code, customer.value):
        # THE STORE WRITE COMES FIRST AND THE ROW FOLLOWS, which is the
        # opposite of the read path's entry row and is chosen for a measurable
        # reason rather than by analogy. Writing the row first would make every
        # failure of the line above -- a Redis timeout, a failover, an ordinary
        # blip on the backend `POSTERN_REDIS_URL` names -- produce a durable
        # row saying a pairing succeeded when none did. This order instead
        # makes "no row" mean "no pairing" on every path but one: a hard
        # process kill between this line and the INSERT, which `PairingAudit`
        # names as the residual.
        return _Pairing(
            JSONResponse(status_code=200, content={"status": "approved"}),
            approved_device_code=existing.device_code,
        )

    return _Pairing(
        _unpairable_response(),
        await _approve_refusal_detail(store, existing.device_code, customer.value),
    )


async def _approve_refusal_detail(
    store: DeviceCodeStoreBase, device_code_value: str, customer_ref: str
) -> str:
    """Which ``DETAIL_*`` a refused ``approve_scanned`` is recorded under.

    Read from the row AFTER the compare-and-set refused, in the order
    ``dev-docs/qr-page-spec.md`` section 6 fixes: gone or expired by now,
    then nobody scanned it, then somebody else did, then it is already
    approved. The read decides nothing -- the refusal has happened -- so the
    race between the two reads can only move a row from one label to another,
    never approve anything.

    A ROW THAT PASSES ALL FOUR is scanned by this customer, unexpired and
    unapproved, which is exactly what ``approve_scanned`` approves. Neither
    backend can refuse such a row: in memory nothing can run between the two
    reads' decisions, and on Redis a transaction beaten on every try raises
    ``DeviceCodeStoreContended`` rather than answering ``False``. So that
    shape raises here too, and ``approve_callback`` records the exception's
    type, which is the true statement.
    """
    row = await store.get_device_code(device_code_value)
    if row is None or row.is_expired:
        return DETAIL_USER_CODE_NOT_FOUND
    if not row.scanned_by:
        return DETAIL_NOT_SCANNED
    if row.scanned_by != customer_ref:
        return DETAIL_SCANNED_BY_OTHER
    if row.approved:
        return DETAIL_ALREADY_APPROVED
    raise RuntimeError("approve_scanned refused a code this customer scanned and has not approved")
```

11i. `device_auth_routes`'s docstring: `settings: Service settings (TTL, URIs, pairing-code attempt budget).` becomes `settings: Service settings (TTL, URIs, poll interval).`

- [ ] **Step 12: Remove the setting, in `services/confirm/settings.py`, `packages/postern-core/src/postern_core/env_inventory.py` and `services/confirm/customer_rate_limit.py`**

12a. `services/confirm/settings.py`: delete the field `user_code_max_attempts: int = 3` and the four comment lines above it (`# RFC 8628 §5.2: bound `user_code` guessing. ...`). In `from_env`, delete from the comment line `# FLOOR OF ONE, and the trace behind it, because the obvious` through the closing `),` of the `user_code_max_attempts=int_from_env(...)` argument (the next line is `# A FLOOR OF ONE BYTE, and deliberately NOT the 8,192 the comment`). In the `max_body_bytes` comment, `` `/approve` carries two`` / ``short codes.`` becomes `` `/approve` carries one`` / ``short code.``.

12b. `packages/postern-core/src/postern_core/env_inventory.py`: delete the row `EnvVar("POSTERN_USER_CODE_MAX_ATTEMPTS", "number", ("confirm",)),`, and replace the comment Task 6 wrote above `INVENTORY` with:

```python
#: Generated from the syntax tree on 2026-09-27 rather than typed, and pinned
#: against it by `tests/test_settings_bounds.py` on every run. 72 rows since
#: 2026-09-30: 27 strings (25 settings plus this guard's own two lists), 42
#: numbers, 3 flags. The eight ``POSTERN_VAULT_*`` rows below the device-code
#: block arrived on 2026-09-29; ``POSTERN_DEVICE_APP_LINK_URI`` and the seven
#: QR-page rate limits arrived on 2026-09-30, the day
#: ``POSTERN_USER_CODE_MAX_ATTEMPTS`` left with the attempt budget it set.
```

12c. `services/confirm/customer_rate_limit.py`, `CustomerRateLimit._refuse`'s docstring, item 3: ``` ``device_code`` in ``POST /approve``'s own body -- where ``` becomes ``` ``user_code`` in ``POST /approve``'s own body -- where ```.

- [ ] **Step 13: Keep the spec's own citations resolvable**

`dev-docs/qr-page-spec.md` section 1, the paragraph that begins "**`update_device_code` and `approve_device_code` are removed**", cites `_record_user_code_failure` in the anchored `<path>.py::<symbol>` form. Once the function is deleted that citation fails `make citations`. Change only that citation, so the sentence reads "... has exactly two production callers, `services/confirm/device_auth.py::_pair` and `_record_user_code_failure` in the same file, both of which this spec rewrites or deletes, ...". Find it with `grep -n "_record_user_code_failure" dev-docs/qr-page-spec.md`; the first hit is the one.

- [ ] **Step 14: Prove no old-contract body or removed name remains**

Run:

```bash
uv run python - <<'EOF'
import ast, pathlib
for path in sorted(pathlib.Path("tests").glob("*.py")):
    for node in ast.walk(ast.parse(path.read_text())):
        if isinstance(node, ast.Dict):
            keys = {k.value for k in node.keys if isinstance(k, ast.Constant)}
            if "device_code" in keys and not keys & {"grant_type", "verification_uri"}:
                print(f"{path} line {node.lineno}")
EOF
```

Expected: no output. (The same script prints 44 lines against the tree before this task: every dict literal carrying `device_code` that is neither a `/token` form nor a serialized `DeviceCode`.)

Run: `grep -rn "update_device_code\|approve_device_code\|user_code_attempts\|user_code_max_attempts\|USER_CODE_MAX_ATTEMPTS\|_record_user_code_failure\|_user_code_matches" tests packages services`
Expected: exactly these nine lines and nothing else -- the two `hasattr` assertions and three lines of the legacy-record test in `tests/test_device_grant.py`, the module docstring of `tests/test_device_code_pairing_store.py`, the `NO WHOLE-SNAPSHOT WRITE` comment and the ignored-key comment in `device_codes.py`, and the row-count comment in `env_inventory.py`.

- [ ] **Step 15: Run the tests to verify they pass**

Run: `uv run pytest tests/test_device_grant.py tests/test_pairing_audit.py tests/test_zt7_confirm_revocation.py tests/test_redis_backed_stores.py tests/test_confirm_auth.py tests/test_confirm_rate_limit.py tests/test_confirm_customer_rate_limit.py tests/test_settings_bounds.py tests/test_device_code_pairing_store.py -q`
Expected: all pass.

- [ ] **Step 16: Format, then run the gate**

Run: `uv run ruff format packages services tests && make ci`
Expected: exit 0. Measured on a copy of the tree with exactly these edits: 3061 passed in 193 seconds.

- [ ] **Step 17: Commit**

```bash
git add tests/device_grant_helpers.py packages/postern-core/src/postern_core/auth/device_codes.py packages/postern-core/src/postern_core/env_inventory.py services/confirm/device_auth.py services/confirm/audit.py services/confirm/settings.py services/confirm/customer_rate_limit.py dev-docs/qr-page-spec.md tests/test_device_grant.py tests/test_pairing_audit.py tests/test_zt7_confirm_revocation.py tests/test_redis_backed_stores.py tests/test_confirm_auth.py tests/test_confirm_rate_limit.py tests/test_confirm_customer_rate_limit.py tests/test_settings_bounds.py
git commit -m "feat(confirm)!: approve a pairing by user_code only, after a scan, by compare-and-set" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 9: `POST /scan`

Spec section 5 in full, and section 7's `/scan` half: `SCAN_TOOL_NAME`, `SCAN_ROUTE`, `DETAIL_QR_INVALID`, `DETAIL_QR_STALE`, `DETAIL_SCAN_CONFLICT`, one row per recorded call, fail-closed withdrawal of a claim. The route is assertion-authenticated, so it is NOT added to `PUBLIC_PATHS`; `tests/test_confirm_auth.py`'s route-table test picks it up by itself and asserts the 401.

**Files:**
- Modify: `services/confirm/audit.py` (`__all__`; new `SCAN_TOOL_NAME`, `SCAN_ROUTE`, `DETAIL_QR_INVALID`, `DETAIL_QR_STALE`, `DETAIL_SCAN_CONFLICT`; `DETAIL_ALREADY_APPROVED`'s first comment paragraph; `PairingAudit`'s first docstring paragraph)
- Modify: `services/confirm/device_auth.py` (module docstring; imports; new section with `_qr_stale_response`, `_scan_conflict_response`, `_scan_context_response`, `_Scanned`, `scan_callback`, `_scan`; `device_auth_routes`)
- Modify: `services/confirm/main.py` (module docstring's endpoint list)
- Create: `tests/test_scan.py`

- [ ] **Step 1: Write the failing test**

Create `tests/test_scan.py`:

```python
"""``POST /scan``: the banking app's half of the QR, over the assembled app.

Every branch of section 5 of ``dev-docs/qr-page-spec.md`` is driven here
through ``create_confirm_app`` and read back out of Postgres, for the reason
``tests/test_pairing_audit.py`` gives: whether a row is written, and what it
carries, is a property of the database and not of a mock.

The rotation token is computed with ``tests/device_grant_helpers.py``'s
``qr_for`` from the stored row's secret, which is what the page would have
drawn; the page itself is ``tests/test_verify_page.py``'s subject.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import patch

import httpx2
import pytest
from fastmcp.server.auth.providers.jwt import JWTVerifier, RSAKeyPair
from postern_core.auth.device_codes import DeviceCode
from postern_core.auth.device_keys import no_enrolled_devices
from postern_core.auth.revocation import RevocationStoreBase, RevocationStoreUnavailable
from postern_core.store import audit as audit_store
from postern_core.store.engine import Database
from postern_core.store.models import (
    ABSENCE_SUBJECT_NOT_A_CUSTOMER_REF,
    OUTCOME_RAISED,
    OUTCOME_RETURNED,
    AuditEntry,
)
from sqlalchemy import select
from starlette.applications import Starlette

from services.confirm.audit import (
    DETAIL_ALREADY_APPROVED,
    DETAIL_INVALID_SUBJECT,
    DETAIL_QR_INVALID,
    DETAIL_QR_STALE,
    DETAIL_REVOKED,
    DETAIL_SCAN_CONFLICT,
    DETAIL_USER_CODE_NOT_FOUND,
    SCAN_ROUTE,
    SCAN_TOOL_NAME,
    device_code_handle,
)
from services.confirm.main import create_confirm_app
from services.confirm.settings import DEFAULT_DEVICE_SCOPES, ConfirmSettings
from tests.device_grant_helpers import device_store_of, overwrite_in_memory, qr_for, stored_code
from tests.fixtures.append_only_bypass import (
    delete_audit_rows_by_bypassing_the_append_only_triggers,
)

ISSUER = "https://app.test.invalid"
AUDIENCE = "postern-confirm"
ALICE = "cust_a11ce"
BOB = "cust_b0b0"
BROWSER_CLIENT = "claude-desktop-42"


# ---------------------------------------------------------------------------
# Fixtures and helpers.
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def key_pair() -> RSAKeyPair:
    return RSAKeyPair.generate()


@pytest.fixture()
def app(pg_url: str, key_pair: RSAKeyPair) -> Starlette:
    """The composition root, pointed at ``tests/conftest.py``'s Postgres."""
    verifier = JWTVerifier(public_key=key_pair.public_key, issuer=ISSUER, audience=AUDIENCE)
    return create_confirm_app(
        replace(ConfirmSettings.for_testing(), database_url=pg_url),
        assertion_verifier=verifier,
        device_key_store=no_enrolled_devices(),
    )


async def _wipe(db: Database) -> None:
    async with db.sessionmaker() as s:
        await delete_audit_rows_by_bypassing_the_append_only_triggers(s)
        await s.commit()


@pytest.fixture()
async def clean(database: Database) -> AsyncIterator[Database]:
    """Empty ``audit_log`` either side of every test, as the pairing audit tests do."""
    await _wipe(database)
    yield database
    await _wipe(database)


def bearer(key_pair: RSAKeyPair, subject: str) -> dict[str, str]:
    token = key_pair.create_token(subject=subject, issuer=ISSUER, audience=AUDIENCE)
    return {"Authorization": f"Bearer {token}"}


async def post(
    app: Starlette,
    path: str,
    *,
    json_body: Any = None,
    form: dict[str, str] | None = None,
    headers: dict[str, str] | None = None,
    as_a_server_would: bool = False,
) -> httpx2.Response:
    """POST over ASGI. ``as_a_server_would`` turns an unhandled exception
    into the 500 a real client receives, as ``tests/test_pairing_audit.py``'s
    ``approve`` does."""
    async with httpx2.AsyncClient(
        transport=httpx2.ASGITransport(app=app, raise_app_exceptions=not as_a_server_would),
        base_url="http://t",
    ) as c:
        if form is not None:
            return await c.post(path, data=form, headers=headers or {})
        return await c.post(path, json=json_body, headers=headers or {})


async def start(app: Starlette) -> DeviceCode:
    """A pairing created the way the browser creates one."""
    resp = await post(app, "/device_authorization", json_body={"client_id": BROWSER_CLIENT})
    assert resp.status_code == 200, resp.text
    return await stored_code(app, resp.json()["user_code"])


async def scan(
    app: Starlette,
    key_pair: RSAKeyPair,
    customer: str,
    code: DeviceCode,
    *,
    qr: str | None = None,
    as_a_server_would: bool = False,
) -> httpx2.Response:
    return await post(
        app,
        "/scan",
        json_body={
            "user_code": code.user_code_display,
            "qr": qr if qr is not None else qr_for(code),
        },
        headers=bearer(key_pair, customer),
        as_a_server_would=as_a_server_would,
    )


async def rows(db: Database) -> list[AuditEntry]:
    async with db.sessionmaker() as s:
        result = await s.execute(select(AuditEntry).order_by(AuditEntry.id))
        return list(result.scalars().all())


async def one_row(db: Database) -> AuditEntry:
    entries = await rows(db)
    assert len(entries) == 1, f"expected exactly one audit row, got {len(entries)}"
    return entries[0]


def forged(code: DeviceCode) -> str:
    """A token for the current slot whose MAC is not the pairing's."""
    slot, mac = qr_for(code).split(".")
    return f"{slot}.{('B' if mac[0] == 'A' else 'A') + mac[1:]}"


# ---------------------------------------------------------------------------
# 1. The scan that claims.
# ---------------------------------------------------------------------------


async def test_a_scan_answers_with_the_stored_context_and_records_one_row(
    app: Starlette, clean: Database, key_pair: RSAKeyPair
) -> None:
    code = await start(app)

    resp = await scan(app, key_pair, ALICE, code)

    assert resp.status_code == 200, resp.text
    assert resp.json() == {
        "client_id": BROWSER_CLIENT,
        "client_id_verified": False,
        "scopes": DEFAULT_DEVICE_SCOPES,
        "expires_at": code.expires_at.isoformat(),
        "user_code": code.user_code_display,
    }
    stored = await device_store_of(app).get_device_code(code.device_code)
    assert stored is not None
    assert stored.scanned_by == ALICE
    assert stored.scanned_at is not None
    assert stored.approved is False

    row = await one_row(clean)
    assert row.outcome == OUTCOME_RETURNED
    assert row.detail is None
    assert row.tool_name == SCAN_TOOL_NAME
    assert row.customer_ref == ALICE
    assert row.arguments["route"] == SCAN_ROUTE
    assert row.arguments["device_code_handle"] == device_code_handle(code.device_code)
    assert row.arguments["paired_client_id"] == BROWSER_CLIENT


async def test_a_retried_scan_by_the_same_customer_answers_the_same(
    app: Starlette, clean: Database, key_pair: RSAKeyPair
) -> None:
    """``already_mine``: a dropped response retried inside the token window."""
    code = await start(app)

    first = await scan(app, key_pair, ALICE, code)
    second = await scan(app, key_pair, ALICE, code)

    assert first.status_code == second.status_code == 200
    assert first.json() == second.json()
    assert [r.outcome for r in await rows(clean)] == [OUTCOME_RETURNED, OUTCOME_RETURNED]


# ---------------------------------------------------------------------------
# 2. Refused before the pairing is looked up.
# ---------------------------------------------------------------------------


async def test_a_subject_that_is_not_a_customer_reference_is_403(
    app: Starlette, clean: Database, key_pair: RSAKeyPair
) -> None:
    code = await start(app)

    resp = await scan(app, key_pair, "4111111111111111", code)

    assert resp.status_code == 403
    assert resp.json()["error"] == "invalid_subject"
    row = await one_row(clean)
    assert row.detail == DETAIL_INVALID_SUBJECT
    assert row.customer_ref is None
    assert row.customer_ref_absence_reason == ABSENCE_SUBJECT_NOT_A_CUSTOMER_REF


async def test_a_revoked_customer_is_403_and_claims_nothing(
    app: Starlette, clean: Database, key_pair: RSAKeyPair
) -> None:
    store: RevocationStoreBase = app.state.postern_revocation_store
    await store.revoke_customer_client(customer_ref=ALICE, client_id=BROWSER_CLIENT)
    code = await start(app)

    resp = await scan(app, key_pair, ALICE, code)

    assert resp.status_code == 403
    assert resp.json()["error"] == "access_revoked"
    row = await one_row(clean)
    assert row.detail == DETAIL_REVOKED
    assert "device_code_handle" not in row.arguments
    stored = await device_store_of(app).get_device_code(code.device_code)
    assert stored is not None and stored.scanned_by == ""


async def test_a_revocation_store_that_cannot_answer_is_a_recorded_500(
    app: Starlette, clean: Database, key_pair: RSAKeyPair
) -> None:
    code = await start(app)

    class Unavailable:
        async def is_customer_revoked(self, customer_ref: str) -> bool:
            raise RevocationStoreUnavailable("the revocation store is gone")

    app.state.postern_revocation_store = Unavailable()

    resp = await scan(app, key_pair, ALICE, code, as_a_server_would=True)

    assert resp.status_code == 500
    assert (await one_row(clean)).detail == "RevocationStoreUnavailable"


# ---------------------------------------------------------------------------
# 3. The one identical invalid_grant, and the detail that tells them apart.
# ---------------------------------------------------------------------------


async def test_an_unknown_user_code_is_invalid_grant(
    app: Starlette, clean: Database, key_pair: RSAKeyPair
) -> None:
    resp = await post(
        app,
        "/scan",
        json_body={"user_code": "ZZZ-ZZZ", "qr": "1.AAAAAAAAAAAAAAAAAAAAAA"},
        headers=bearer(key_pair, ALICE),
    )

    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_grant"
    row = await one_row(clean)
    assert row.detail == DETAIL_USER_CODE_NOT_FOUND
    assert "device_code_handle" not in row.arguments


async def test_an_expired_code_is_invalid_grant(
    app: Starlette, clean: Database, key_pair: RSAKeyPair
) -> None:
    code = await start(app)
    overwrite_in_memory(app, replace(code, expires_at=datetime.now(UTC) - timedelta(seconds=1)))

    resp = await scan(app, key_pair, ALICE, code)

    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_grant"
    assert (await one_row(clean)).detail == DETAIL_USER_CODE_NOT_FOUND


async def test_a_code_this_customer_already_approved_is_invalid_grant(
    app: Starlette, clean: Database, key_pair: RSAKeyPair
) -> None:
    """``approved_mine``: nothing new to show, so nothing distinct to say."""
    code = await start(app)
    assert (await scan(app, key_pair, ALICE, code)).status_code == 200
    assert await device_store_of(app).approve_scanned(code.device_code, ALICE) is True
    await _wipe(clean)

    resp = await scan(app, key_pair, ALICE, code)

    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_grant"
    assert (await one_row(clean)).detail == DETAIL_ALREADY_APPROVED


@pytest.mark.parametrize("shape", ["forged mac", "future slot", "malformed"])
async def test_a_token_that_does_not_verify_is_invalid_grant_and_claims_nothing(
    app: Starlette, clean: Database, key_pair: RSAKeyPair, shape: str
) -> None:
    code = await start(app)
    token = {
        "forged mac": forged(code),
        # Three, not two: a slot boundary can pass between computing the
        # token and the server checking it, and +3 is still beyond +1 then.
        "future slot": qr_for(code, slot_offset=3),
        "malformed": "not-a-token",
    }[shape]

    resp = await scan(app, key_pair, ALICE, code, qr=token)

    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_grant"
    row = await one_row(clean)
    assert row.detail == DETAIL_QR_INVALID
    assert row.arguments["device_code_handle"] == device_code_handle(code.device_code)
    stored = await device_store_of(app).get_device_code(code.device_code)
    assert stored is not None and stored.scanned_by == ""


async def test_unknown_expired_approved_and_forged_answer_one_identical_body(
    app: Starlette, clean: Database, key_pair: RSAKeyPair
) -> None:
    """The existence oracle closed: four causes, one body, four details."""
    expired = await start(app)
    overwrite_in_memory(app, replace(expired, expires_at=datetime.now(UTC) - timedelta(seconds=1)))
    approved = await start(app)
    assert (await scan(app, key_pair, ALICE, approved)).status_code == 200
    await device_store_of(app).approve_scanned(approved.device_code, ALICE)
    live = await start(app)
    await _wipe(clean)

    answers = [
        await post(
            app,
            "/scan",
            json_body={"user_code": "ZZZ-ZZZ", "qr": "1.AAAAAAAAAAAAAAAAAAAAAA"},
            headers=bearer(key_pair, ALICE),
        ),
        await scan(app, key_pair, ALICE, expired),
        await scan(app, key_pair, ALICE, approved),
        await scan(app, key_pair, ALICE, live, qr=forged(live)),
    ]

    assert {r.status_code for r in answers} == {400}
    assert all(r.json() == answers[0].json() for r in answers), [r.json() for r in answers]
    assert [r.detail for r in await rows(clean)] == [
        DETAIL_USER_CODE_NOT_FOUND,
        DETAIL_USER_CODE_NOT_FOUND,
        DETAIL_ALREADY_APPROVED,
        DETAIL_QR_INVALID,
    ]


# ---------------------------------------------------------------------------
# 4. The two distinct answers: a stale QR, and a pairing another phone holds.
# ---------------------------------------------------------------------------


async def test_a_genuine_token_past_the_window_is_qr_stale(
    app: Starlette, clean: Database, key_pair: RSAKeyPair
) -> None:
    """The screenshot relay, refused and recorded, with nothing claimed."""
    code = await start(app)

    resp = await scan(app, key_pair, ALICE, code, qr=qr_for(code, slot_offset=-6))

    assert resp.status_code == 400
    assert resp.json()["error"] == "qr_stale"
    row = await one_row(clean)
    assert row.outcome == OUTCOME_RAISED
    assert row.detail == DETAIL_QR_STALE
    stored = await device_store_of(app).get_device_code(code.device_code)
    assert stored is not None and stored.scanned_by == ""


async def test_a_stale_token_from_another_customer_revokes_nothing(
    app: Starlette, clean: Database, key_pair: RSAKeyPair
) -> None:
    """The MAC is checked before the claim, so only a scan inside the window
    reaches session-swap detection."""
    code = await start(app)
    assert (await scan(app, key_pair, ALICE, code)).status_code == 200

    resp = await scan(app, key_pair, BOB, code, qr=qr_for(code, slot_offset=-6))

    assert resp.json()["error"] == "qr_stale"
    stored = await device_store_of(app).get_device_code(code.device_code)
    assert stored is not None and stored.scanned_by == ALICE
    assert [r.detail for r in await rows(clean)] == [None, DETAIL_QR_STALE]


async def test_session_swap_before_the_exchange_revokes_the_pairing(
    app: Starlette, clean: Database, key_pair: RSAKeyPair
) -> None:
    """B scans A's QR first; A's own scan ends the pairing, and A's AI client
    receives nothing on its next poll rather than B's accounts."""
    code = await start(app)
    assert (await scan(app, key_pair, BOB, code)).status_code == 200

    resp = await scan(app, key_pair, ALICE, code)

    assert resp.status_code == 400
    assert resp.json()["error"] == "scan_conflict"
    assert await device_store_of(app).get_device_code(code.device_code) is None
    poll = await post(
        app, "/token", form={"grant_type": "device_code", "device_code": code.device_code}
    )
    assert poll.status_code == 400
    assert poll.json()["error"] == "invalid_grant"
    written = await rows(clean)
    assert [(r.customer_ref, r.detail) for r in written] == [
        (BOB, None),
        (ALICE, DETAIL_SCAN_CONFLICT),
    ]


async def test_session_swap_after_the_exchange_is_refused_with_nothing_revoked(
    app: Starlette, clean: Database, key_pair: RSAKeyPair
) -> None:
    """The window this spec does not close: B's token is already out. The
    conflict is refused and recorded; the spent row is left exactly as it was,
    because revoking it would recall nothing."""
    code = await start(app)
    assert (await scan(app, key_pair, BOB, code)).status_code == 200
    assert await device_store_of(app).approve_scanned(code.device_code, BOB) is True
    exchanged = await post(
        app, "/token", form={"grant_type": "device_code", "device_code": code.device_code}
    )
    assert exchanged.status_code == 200
    before = await device_store_of(app).get_device_code(code.device_code)

    resp = await scan(app, key_pair, ALICE, code)

    assert resp.status_code == 400
    assert resp.json()["error"] == "scan_conflict"
    assert await device_store_of(app).get_device_code(code.device_code) == before
    assert (await rows(clean))[-1].detail == DETAIL_SCAN_CONFLICT


async def test_the_two_distinct_answers_are_distinct_from_invalid_grant(
    app: Starlette, clean: Database, key_pair: RSAKeyPair
) -> None:
    stale_code = await start(app)
    stale = await scan(app, key_pair, ALICE, stale_code, qr=qr_for(stale_code, slot_offset=-6))
    swapped = await start(app)
    await scan(app, key_pair, BOB, swapped)
    conflict = await scan(app, key_pair, ALICE, swapped)
    unknown = await post(
        app,
        "/scan",
        json_body={"user_code": "ZZZ-ZZZ", "qr": "1.AAAAAAAAAAAAAAAAAAAAAA"},
        headers=bearer(key_pair, ALICE),
    )

    errors = {stale.json()["error"], conflict.json()["error"], unknown.json()["error"]}
    assert errors == {"qr_stale", "scan_conflict", "invalid_grant"}


# ---------------------------------------------------------------------------
# 5. What writes no row, and what fails closed.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "body",
    [
        pytest.param([1, 2, 3], id="a JSON array"),
        pytest.param({}, id="neither field"),
        pytest.param({"user_code": "ABC-DEF"}, id="no qr"),
        pytest.param({"qr": "1.x"}, id="no user_code"),
        pytest.param({"user_code": 123, "qr": "1.x"}, id="user_code is a number"),
        pytest.param({"user_code": "ABC-DEF", "qr": ["x"]}, id="qr is a list"),
        pytest.param({"user_code": "", "qr": "1.x"}, id="user_code is empty"),
    ],
)
async def test_a_malformed_body_is_invalid_request_with_no_row(
    app: Starlette, clean: Database, key_pair: RSAKeyPair, body: Any
) -> None:
    resp = await post(app, "/scan", json_body=body, headers=bearer(key_pair, ALICE))

    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_request"
    assert await rows(clean) == []


async def test_no_assertion_is_401_with_no_row(app: Starlette, clean: Database) -> None:
    resp = await post(app, "/scan", json_body={"user_code": "ABC-DEF", "qr": "1.x"})

    assert resp.status_code == 401
    assert await rows(clean) == []


async def test_a_claim_that_cannot_be_audited_is_withdrawn(
    app: Starlette, clean: Database, key_pair: RSAKeyPair
) -> None:
    """Asserted on the STORE: a claim nobody recorded would still decide who
    may approve."""
    code = await start(app)

    async def unavailable(session: Any, **kw: Any) -> None:
        raise RuntimeError("audit store unavailable")

    with patch.object(audit_store, "append", unavailable):
        resp = await scan(app, key_pair, ALICE, code, as_a_server_would=True)

    assert resp.status_code == 500
    assert await rows(clean) == []
    assert await device_store_of(app).get_device_code(code.device_code) is None


async def test_a_repeat_scan_that_cannot_be_audited_withdraws_nothing(
    app: Starlette, clean: Database, key_pair: RSAKeyPair
) -> None:
    """The first scan's claim was recorded when it was made; a retry that
    fails to write its own row must not undo it."""
    code = await start(app)
    assert (await scan(app, key_pair, ALICE, code)).status_code == 200

    async def unavailable(session: Any, **kw: Any) -> None:
        raise RuntimeError("audit store unavailable")

    with patch.object(audit_store, "append", unavailable):
        resp = await scan(app, key_pair, ALICE, code, as_a_server_would=True)

    assert resp.status_code == 500
    stored = await device_store_of(app).get_device_code(code.device_code)
    assert stored is not None and stored.scanned_by == ALICE
```

- [ ] **Step 2: Run it to verify it fails**

Run: `uv run pytest tests/test_scan.py -q`
Expected: collection error, `ImportError: cannot import name 'DETAIL_QR_INVALID' from 'services.confirm.audit'`.

- [ ] **Step 3: Add the audit literals, in `services/confirm/audit.py`**

3a. `__all__` gains `"SCAN_ROUTE",` and `"SCAN_TOOL_NAME",` (after `"PAIRING_TOOL_NAME",`), `"DETAIL_QR_INVALID",` and `"DETAIL_QR_STALE",` (after `"DETAIL_NOT_SCANNED",`), and `"DETAIL_SCAN_CONFLICT",` (after `"DETAIL_SCANNED_BY_OTHER",`).

3b. Directly after `TOKEN_ROUTE = "/token"  # noqa: S105`, add:

```python

#: What ``tool_name`` carries on a ``POST /scan`` row.
#:
#: ITS OWN LITERAL, for the reason ``TOKEN_TOOL_NAME`` has one: "which
#: pairings were scanned" and "which were approved" differ exactly when a scan
#: conflicts or a code is scanned and abandoned, and one literal would hide
#: both. Under ``device_grant.*`` like the other two, so
#: ``WHERE tool_name LIKE 'device_grant.%'`` still returns the whole flow, and
#: none of the five registered MCP tools.
SCAN_TOOL_NAME = "device_grant.scan"

#: The route, in ``arguments`` for the reason ``PAIRING_ROUTE`` is there.
SCAN_ROUTE = "/scan"
```

3c. Directly after `DETAIL_SCANNED_BY_OTHER = "scanned_by_other"` (Task 8), add:

```python
#: ``POST /scan`` with a rotation token that is malformed, forged, for another
#: pairing, or for a slot ahead of the server's window. Answered with the same
#: ``invalid_grant`` as an unknown code, because nothing about it proves the
#: caller ever held a real QR.
DETAIL_QR_INVALID = "qr_invalid"
#: ``POST /scan`` with a genuine token older than the window. The direct trace
#: of a screenshot relay, and the one refusal here answered with its own
#: ``qr_stale``: a MAC that verifies proves the caller held a real QR for this
#: pairing, so telling them to scan again leaks nothing they did not know.
DETAIL_QR_STALE = "qr_stale"
#: ``POST /scan`` by a second customer inside the token window, whether the
#: pairing was revoked by it (``ScanClaim.CONFLICT_REVOKED``) or had already
#: been exchanged (``ScanClaim.CONFLICT_EXCHANGED``). The trace of one QR seen
#: by two phones, and of a session swap attempted in either order.
DETAIL_SCAN_CONFLICT = "scan_conflict"
```

3d. `DETAIL_ALREADY_APPROVED`'s comment, first two lines as Task 8 left them,

```python
#: A repeat approval by the customer who scanned the code, normally a retried
#: request, at ``POST /approve`` when the code is already approved.
```

become

```python
#: A repeat approval by the customer who scanned the code, normally a retried
#: request: at ``POST /approve`` when the code is already approved, and at
#: ``POST /scan`` through ``ScanClaim.APPROVED_MINE``.
```

3e. `PairingAudit`'s docstring, first paragraph: replace

```
    TWO ENDPOINTS, ONE WRITER. ``POST /approve`` pairs a client and
    ``POST /token`` mints the read token that pairing authorises; both write
    through this class, which is why ``tool_name`` and ``route`` are
    constructor arguments. ``POST /device_authorization``, the third endpoint
    of the grant, writes nothing at all -- see the rule below and that
    handler's own docstring.
```

with

```
    THREE ENDPOINTS, ONE WRITER. ``POST /scan`` claims a pairing for the
    customer whose app scanned it, ``POST /approve`` pairs the client, and
    ``POST /token`` mints the read token that pairing authorises; all three
    write through this class, which is why ``tool_name`` and ``route`` are
    constructor arguments. ``POST /device_authorization``, where the grant
    begins, writes nothing at all -- see the rule below and that handler's
    own docstring.
```

- [ ] **Step 4: Add the handler, in `services/confirm/device_auth.py`**

4a. Imports: add `ScanClaim,` after `DeviceCodeStoreFull,` in the `from postern_core.auth.device_codes import (...)` block; in the `from services.confirm.audit import (...)` block add `DETAIL_QR_INVALID,` and `DETAIL_QR_STALE,` after `DETAIL_NOT_SCANNED,`, `DETAIL_SCAN_CONFLICT,` after `DETAIL_REVOKED,`, and `SCAN_ROUTE,` and `SCAN_TOOL_NAME,` before `TOKEN_ROUTE,`; and add `from services.confirm.qr_token import QrVerdict, slot_at, verify_token` directly after `from services.confirm.auth import unauthenticated_response, verified_claims, verified_subject`.

4b. Module docstring. In the endpoint list, add after the `POST /token` item:

```
- ``POST /scan`` -- Mobile app scan of the QR (binds the pairing to the first
  customer who presents a current rotation token).
```

and replace the two paragraphs `WHO IS AUTHENTICATED, AND WHO IS NOT. ...` and `WHO CAN BE CUT, AND WHERE (ZT-7). ...` with:

```
WHO IS AUTHENTICATED, AND WHO IS NOT. ``POST /scan`` and ``POST /approve``
are the banking app, which must present a bearer assertion the operator's app
backend minted; ``services/confirm/auth.py`` verifies it and this module
takes the customer from the verified ``sub``. ``POST /device_authorization``
and ``POST /token`` are the BROWSER, which by the device grant's premise
holds no credential at all, and they are named in that module's
``PUBLIC_PATHS`` with the reason.

WHO CAN BE CUT, AND WHERE (ZT-7). All three endpoints that know a customer
refuse a revoked one: ``POST /scan`` and ``POST /approve`` on the assertion's
``sub``, before the device code is touched, and ``POST /token`` on the
``customer_ref`` stored on the device code, before the read token is minted.
Nothing is keyed on ``DeviceCode.client_id`` -- the browser supplies it
unauthenticated at ``POST /device_authorization``, so a kill switch enforced
on it would be theatre. ``services/confirm/revocation.py`` holds the full
argument.
```

4c. Directly before the `# Route assembly.` banner (before its upper rule line), add the new section:

```python
# Scan -- POST /scan.
#
# Called by the operator's banking app the moment it reads the QR, before the
# user has compared anything. It is the step that binds a pairing to ONE
# customer: the first customer to present a current rotation token for a
# pairing becomes its ``scanned_by``, and ``POST /approve`` approves for that
# customer and nobody else. ``dev-docs/qr-page-spec.md`` section 5 is the
# contract; the decisions below are the ones that section leaves to code.
#
# The app sends ``user_code`` and ``qr``, both read from the app link the QR
# encodes, and nothing that names a customer: that comes from the verified
# assertion's ``sub``, as on every other assertion-authenticated path.


def _qr_stale_response() -> JSONResponse:
    """A genuine rotation token that has aged out of the window.

    DISTINCT FROM ``_unpairable_response`` on purpose, and safe to be: only a
    MAC that verifies reaches it, and a caller holding one already knows the
    pairing exists. The app needs the difference to say "scan again".
    """
    return _error(400, "qr_stale", "the QR code has changed; scan the one on screen now")


def _scan_conflict_response() -> JSONResponse:
    """A second customer's scan of a pairing another customer holds.

    Distinct for the reason ``_qr_stale_response`` gives, and the app needs it
    to say "this pairing was cancelled". Reached only past a verifying MAC.
    """
    return _error(400, "scan_conflict", "this pairing was scanned by another device")


def _scan_context_response(code: DeviceCode) -> JSONResponse:
    """What the app shows beside the pairing code the user reads off the page.

    EVERY VALUE COMES FROM THE STORED ROW and none from the QR or the body, so
    a tampered QR cannot change what the confirmation screen says.
    ``client_id_verified`` is ``False`` on every answer because nothing on
    this path verifies it: the browser supplied ``client_id``, unauthenticated,
    at ``POST /device_authorization``, and until CIMD verification exists the
    app must not present it as an identity.
    """
    return JSONResponse(
        status_code=200,
        content={
            "client_id": code.client_id,
            "client_id_verified": False,
            "scopes": code.scopes,
            "expires_at": code.expires_at.isoformat(),
            "user_code": code.user_code_display,
        },
    )


@dataclasses.dataclass(frozen=True, slots=True)
class _Scanned:
    """What ``_scan`` decided, and what the caller owes ``audit_log`` for it.

    The shape of ``_Pairing``, one endpoint over, for the same reasons.
    """

    response: JSONResponse
    detail: str | None = None
    recorded: bool = True
    #: The device code this exit CLAIMED, so the caller can withdraw the claim
    #: if the row cannot be written. ``None`` on every other exit, including a
    #: repeat by the same customer: that claim was recorded when it was made.
    claimed_device_code: str | None = None


async def scan_callback(request: Request) -> JSONResponse:
    """The banking app's scan of a pairing QR, and its audit row.

    Requires a verified app assertion (``services/confirm/auth.py``); it is
    not in ``PUBLIC_PATHS``. The customer is the assertion's ``sub``.

    Request body:
        user_code: From the app link the QR encodes, ``XXX-XXX`` or bare.
        qr: The rotation token from the same link, ``<slot>.<mac>``.

    Response (200): the stored pairing's context; see ``_scan_context_response``.
    Response (400): ``invalid_request`` for a malformed body; ``qr_stale``;
        ``scan_conflict``; and the one ``invalid_grant`` body of
        ``_unpairable_response`` for an unknown or expired code, an approved
        one, and a malformed, forged or future rotation token.
    Response (401): no verified assertion.
    Response (403): ``invalid_subject`` or ``access_revoked`` (ZT-7).

    ONE ROW PER RECORDED CALL, through ``PairingAudit`` with
    ``SCAN_TOOL_NAME`` and ``SCAN_ROUTE``, fail-closed per decision 0006: a
    claim whose row cannot be written is withdrawn exactly as
    ``_withdraw_pairing`` withdraws an unrecorded approval. The malformed-body
    exits write nothing, by ``PairingAudit``'s rule, as on ``POST /approve``.
    """
    at = datetime.now(UTC)
    started = time.monotonic()

    subject = verified_subject(request)
    if subject is None:
        # Unreachable through the assembled app, and no row: the backstop
        # `approve_callback` keeps, for the reason it gives.
        return unauthenticated_response()

    settings: ConfirmSettings = request.app.state.settings
    db: Database = request.app.state.postern_database
    store: DeviceCodeStoreBase = request.app.state.device_code_store

    audit = PairingAudit(
        db=db,
        call_id=str(uuid.uuid4()),
        at=at,
        started=started,
        subject=subject,
        claims=verified_claims(request),
        client_ip_value=pairing_client_ip(request, settings.trusted_proxy_hops),
        tool_name=SCAN_TOOL_NAME,
        route=SCAN_ROUTE,
    )

    try:
        outcome = await _scan(request, audit, store=store, subject=subject)
    except Exception as exc:
        # The shape `approve_callback` uses: an audit-write failure must not
        # replace the exception that ended the request. Nothing was claimed
        # on a path that raises -- `claim_scan` either commits and returns or
        # raises having written nothing -- so there is nothing to withdraw.
        try:
            await audit.refused(type(exc).__name__)
        except Exception as audit_exc:
            logger.error(
                "audit write failed for a device pairing scan after it raised %s: %s",
                type(exc).__name__,
                audit_exc,
                exc_info=audit_exc,
            )
            raise exc from audit_exc
        raise

    if not outcome.recorded:
        return outcome.response

    try:
        if outcome.detail is None:
            await audit.approved()
        else:
            await audit.refused(outcome.detail)
    except Exception as audit_exc:
        # FAIL CLOSED BY WITHDRAWING THE CLAIM, for the reason
        # `approve_callback` withdraws an approval: a claim nobody recorded
        # would still decide who may approve, and no row would say who made it.
        if outcome.claimed_device_code is not None:
            await _withdraw_pairing(store, outcome.claimed_device_code)
        logger.error(
            "audit write failed for a device pairing scan that answered %d; "
            "failing the request because the scan could not be recorded",
            outcome.response.status_code,
            exc_info=audit_exc,
        )
        raise
    return outcome.response


async def _scan(
    request: Request,
    audit: PairingAudit,
    *,
    store: DeviceCodeStoreBase,
    subject: str,
) -> _Scanned:
    """The scan itself, in section 5's order, returning what the row owes.

    THE MAC IS CHECKED BEFORE THE CLAIM, and that order is what keeps session
    swap detection honest. A stale token from a second customer answers
    ``qr_stale`` and revokes nothing, because only a caller inside the token
    window -- one who could have been standing at the screen -- reaches
    ``claim_scan`` at all.
    """
    try:
        customer = CustomerRef(value=subject)
    except ValidationError:
        # As at `POST /approve`: a genuine assertion with a non-conforming
        # `sub`, never echoed or logged, recorded as an absence.
        logger.warning("device scan: assertion subject is not a customer reference")
        return _Scanned(
            _error(403, "invalid_subject", "assertion subject is not a customer reference"),
            DETAIL_INVALID_SUBJECT,
        )

    # ZT-7 before anything is read, as at `POST /approve`, and with the same
    # consequences: `RevocationStoreUnavailable` propagates to a 500 recorded
    # under the exception's type, and the row names no pairing.
    if await customer_revoked(request, customer.value):
        log_refusal("a device pairing scan")
        return _Scanned(
            revoked_response("this customer's access has been revoked"),
            DETAIL_REVOKED,
        )

    try:
        body = await request.json()
    except (json.JSONDecodeError, UnicodeDecodeError):
        return _Scanned(_error(400, "invalid_request", "body must be JSON"), recorded=False)
    if not isinstance(body, dict):
        return _Scanned(
            _error(400, "invalid_request", "body must be a JSON object"), recorded=False
        )

    user_code_value = body.get("user_code", "")
    qr_value = body.get("qr", "")
    if not isinstance(user_code_value, str) or not isinstance(qr_value, str):
        return _Scanned(
            _error(400, "invalid_request", "user_code and qr must be strings"), recorded=False
        )
    if not user_code_value or not qr_value:
        return _Scanned(
            _error(400, "invalid_request", "user_code and qr are required"), recorded=False
        )

    code = await _lookup_by_user_code(store, user_code_value)
    if code is None:
        return _Scanned(_unpairable_response(), DETAIL_USER_CODE_NOT_FOUND)

    audit.names(device_code=code.device_code, paired_client_id=code.client_id)

    verdict = verify_token(code.qr_secret, code.user_code, qr_value, slot_at(time.time()))
    if verdict is QrVerdict.INVALID:
        return _Scanned(_unpairable_response(), DETAIL_QR_INVALID)
    if verdict is QrVerdict.STALE:
        return _Scanned(_qr_stale_response(), DETAIL_QR_STALE)

    claim = await store.claim_scan(code.device_code, customer.value)
    if claim is ScanClaim.CLAIMED:
        return _Scanned(_scan_context_response(code), claimed_device_code=code.device_code)
    if claim is ScanClaim.ALREADY_MINE:
        return _Scanned(_scan_context_response(code))
    if claim is ScanClaim.APPROVED_MINE:
        return _Scanned(_unpairable_response(), DETAIL_ALREADY_APPROVED)
    if claim is ScanClaim.CONFLICT_REVOKED or claim is ScanClaim.CONFLICT_EXCHANGED:
        # A LOG LINE AS WELL AS THE ROW, because this is the event an operator
        # may want to alert on at the edge. The handle, never the code.
        logger.warning(
            "device scan: pairing %s scanned by a second customer (%s)",
            device_code_handle(code.device_code),
            claim.value,
        )
        return _Scanned(_scan_conflict_response(), DETAIL_SCAN_CONFLICT)
    return _Scanned(_unpairable_response(), DETAIL_USER_CODE_NOT_FOUND)
```

and put a `# ---------------------------------------------------------------------------` rule line directly above its `# Scan -- POST /scan.` title line, matching the other banners.

4d. `device_auth_routes`: add the route between `/token` and `/approve`:

```python
        Route(
            "/scan",
            scan_callback,
            methods=["POST"],
        ),
```

- [ ] **Step 5: `services/confirm/main.py`'s module docstring**

In the device authorization endpoint list, add `- ``POST /scan`` -- Mobile app scan of the pairing QR.` directly above `- ``POST /approve`` — Mobile app approval callback.`

- [ ] **Step 6: Run the tests to verify they pass**

Run: `uv run pytest tests/test_scan.py tests/test_confirm_auth.py tests/test_device_grant.py tests/test_pairing_audit.py -q`
Expected: all pass. `tests/test_confirm_auth.py::test_every_non_public_route_denies_an_unauthenticated_caller` now includes `POST /scan` and passes unchanged.

- [ ] **Step 7: Format, then run the gate**

Run: `uv run ruff format packages services tests && make ci`
Expected: exit 0.

- [ ] **Step 8: Commit**

```bash
git add services/confirm/audit.py services/confirm/device_auth.py services/confirm/main.py tests/test_scan.py
git commit -m "feat(confirm): add POST /scan, the first-scan-wins claim behind every approval" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 10: The pairing page, its QR, its state, its script and its stylesheet

Spec section 4 in full: the five public routes as plain `Route`s, every header, the three-state table, the noscript refresh, stored-value rendering, the hotlink refusal, `segno` for the SVG, and `PUBLIC_PATHS` growing to eight.

**Files:**
- Modify: `pyproject.toml`, `uv.lock` (via `uv add`)
- Create: `services/confirm/verify_page.py`
- Create: `services/confirm/static/verify.js`
- Create: `services/confirm/static/verify.css`
- Modify: `services/confirm/auth.py` (`PUBLIC_PATHS` and its comment)
- Modify: `services/confirm/main.py` (import; route list; module docstring)
- Modify: `services/confirm/customer_rate_limit.py` (two comments that count the public paths)
- Create: `tests/test_verify_page.py`
- Modify: `tests/test_confirm_auth.py` (`test_the_public_path_list_is_exactly_these_three` becomes `..._these_eight`; new `test_every_public_path_is_a_route_with_methods`)
- Modify: `tests/test_confirm_body_limit.py` (`test_every_route_is_covered_including_the_public_and_form_encoded_ones`)

- [ ] **Step 1: Add the dependency**

Run: `uv add "segno>=1.6.6,<2"`
Expected: `+ segno==1.6.6`; `pyproject.toml`'s `dependencies` gains `"segno>=1.6.6,<2",` after `"alembic>=1.20,<2",`, and `uv.lock` gains the `segno` 1.6.6 package entry (11 lines). It goes in the root `pyproject.toml` because `services/` is not a distribution; it therefore lands in the shared serving environment and in the api image too, as the spec says. Then confirm the API this task relies on: `uv run python -c "import inspect, segno; print(segno.__version__, inspect.signature(segno.make_qr))"` prints `1.6.6 (content, error=None, version=None, mode=None, mask=None, encoding=None, eci=False, boost_error=True)`.

- [ ] **Step 2: Write the failing tests**

2a. Create `tests/test_verify_page.py`:

```python
"""The five public pairing-page routes, over the assembled app.

Section 4 of ``dev-docs/qr-page-spec.md``: every header on every route, the
three rows of the page-state table, the stored values rendered instead of the
query's, the state endpoint's bodies, the image's 404s, and the hotlink
refusal on the image and the state. No Postgres: none of these routes reads or
writes ``audit_log``, and the app builds without connecting.
"""

from __future__ import annotations

import time
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from urllib.parse import parse_qs, quote, urlsplit

import httpx2
import pytest
from fastmcp.server.auth.providers.jwt import JWTVerifier, RSAKeyPair
from postern_core.auth.device_codes import DeviceCode
from postern_core.auth.device_keys import no_enrolled_devices
from starlette.applications import Starlette

from services.confirm import verify_page
from services.confirm.main import create_confirm_app
from services.confirm.qr_token import QrVerdict, slot_at, verify_token
from services.confirm.settings import ConfirmSettings
from services.confirm.verify_page import (
    CLOSED_TEXT,
    NO_HANDLE_TEXT,
    PAGE_CSP,
    PENDING_TEXT,
    SCANNED_TEXT,
)
from tests.device_grant_helpers import device_store_of, overwrite_in_memory

SAME_ORIGIN = {"Sec-Fetch-Site": "same-origin"}
CUSTOMER = "cust_7f3a"
CLOSED_STATES = ["unknown", "expired", "approved"]


@pytest.fixture(scope="module")
def key_pair() -> RSAKeyPair:
    return RSAKeyPair.generate()


@pytest.fixture()
def app(key_pair: RSAKeyPair) -> Starlette:
    return create_confirm_app(
        ConfirmSettings.for_testing(),
        assertion_verifier=JWTVerifier(
            public_key=key_pair.public_key, issuer="https://i.test", audience="a"
        ),
        device_key_store=no_enrolled_devices(),
    )


async def get(app: Starlette, path: str, headers: dict[str, str] | None = None) -> httpx2.Response:
    async with httpx2.AsyncClient(
        transport=httpx2.ASGITransport(app=app), base_url="http://test"
    ) as client:
        return await client.get(path, headers=headers or {})


async def pairing(app: Starlette, state: str) -> DeviceCode:
    """A stored pairing in ``state``: pending, scanned, expired or approved."""
    store = device_store_of(app)
    code = await store.create_device_code(
        client_id="browser-1", scopes="accounts:read", verification_uri="https://a.test/verify"
    )
    if state in ("scanned", "approved"):
        await store.claim_scan(code.device_code, CUSTOMER)
    if state == "approved":
        assert await store.approve_scanned(code.device_code, CUSTOMER) is True
    if state == "expired":
        overwrite_in_memory(app, replace(code, expires_at=datetime.now(UTC) - timedelta(seconds=1)))
    return code


async def handle_for(app: Starlette, state: str) -> str:
    """The ``d`` value for a pairing in ``state``; ``unknown`` names none."""
    if state == "unknown":
        return "no-such-handle-0000000"
    return (await pairing(app, state)).display_handle


def page_url(handle: str) -> str:
    return f"/verify?d={quote(handle, safe='')}"


# ---------------------------------------------------------------------------
# GET /verify
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("state", ["bare", "pending", "scanned", *CLOSED_STATES])
async def test_the_page_carries_every_header_in_every_state(app: Starlette, state: str) -> None:
    url = "/verify" if state == "bare" else page_url(await handle_for(app, state))

    resp = await get(app, url)

    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/html")
    assert resp.headers["content-security-policy"] == PAGE_CSP
    assert resp.headers["referrer-policy"] == "no-referrer"
    assert resp.headers["cache-control"] == "no-store"
    assert resp.headers["x-content-type-options"] == "nosniff"
    assert resp.headers["strict-transport-security"] == "max-age=31536000"
    assert resp.headers["x-frame-options"] == "DENY"


def test_the_csp_is_the_specs_to_the_character() -> None:
    assert PAGE_CSP == (
        "default-src 'none'; img-src 'self'; script-src 'self'; style-src 'self'; "
        "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
    )


async def test_a_pending_page_shows_the_code_the_qr_the_link_and_the_instruction(
    app: Starlette,
) -> None:
    code = await pairing(app, "pending")

    page = (await get(app, page_url(code.display_handle))).text

    assert code.user_code_display in page
    assert f'<img id="qr" src="/verify/qr.svg?d={code.display_handle}"' in page
    assert 'id="app-link" href="https://app.postern.internal/pair?user_code=' in page
    assert PENDING_TEXT in page
    assert '<meta http-equiv="refresh" content="5">' in page
    assert '<script src="/verify.js" defer></script>' in page
    assert '<link rel="stylesheet" href="/verify.css">' in page
    assert "<script>" not in page, "no inline script: the CSP would refuse it anyway"


async def test_a_scanned_page_shows_the_code_and_nothing_to_scan(app: Starlette) -> None:
    code = await pairing(app, "scanned")

    page = (await get(app, page_url(code.display_handle))).text

    assert code.user_code_display in page
    assert 'id="qr"' not in page
    assert 'id="app-link"' not in page
    assert SCANNED_TEXT in page
    assert '<meta http-equiv="refresh" content="5">' in page


async def test_every_closed_page_is_the_same_page(app: Starlette) -> None:
    """Unknown, expired and approved are indistinguishable, so the page
    confirms nothing about an approval."""
    pages = [(await get(app, page_url(await handle_for(app, s)))).text for s in CLOSED_STATES]

    assert pages[0] == pages[1] == pages[2]
    assert CLOSED_TEXT in pages[0]
    assert 'id="pairing-code"' not in pages[0]
    assert 'id="qr"' not in pages[0]
    assert 'http-equiv="refresh"' not in pages[0]
    assert "/verify.js" not in pages[0]


async def test_a_bare_page_says_one_sentence_and_offers_no_form(app: Starlette) -> None:
    page = (await get(app, "/verify")).text

    assert NO_HANDLE_TEXT in page
    assert "<form" not in page
    assert "<input" not in page
    assert 'http-equiv="refresh"' not in page


async def test_the_page_renders_the_stored_values_and_not_the_query(
    app: Starlette, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The lookup is replaced by one that ignores its argument, so the only
    way the probe string could reach the page is from the query."""
    stored = replace(await pairing(app, "pending"), display_handle="stored-handle-00000000")

    async def found_regardless(display_handle: str) -> DeviceCode:
        return stored

    monkeypatch.setattr(device_store_of(app), "get_by_display_handle", found_regardless)

    page = (await get(app, "/verify?d=probe-from-the-query")).text

    assert "stored-handle-00000000" in page
    assert stored.user_code_display in page
    assert "probe-from-the-query" not in page


async def test_markup_in_the_query_never_reaches_the_page(app: Starlette) -> None:
    page = (await get(app, "/verify?d=%3Cscript%3Ealert(1)%3C%2Fscript%3E")).text

    assert "alert(1)" not in page
    assert CLOSED_TEXT in page


# ---------------------------------------------------------------------------
# GET /verify/state
# ---------------------------------------------------------------------------


def assert_state_headers(resp: httpx2.Response) -> None:
    assert resp.headers["content-type"].startswith("application/json")
    assert resp.headers["cache-control"] == "no-store"
    assert resp.headers["x-content-type-options"] == "nosniff"
    assert resp.headers["cross-origin-resource-policy"] == "same-origin"


async def test_a_pending_state_carries_a_current_app_link(app: Starlette) -> None:
    code = await pairing(app, "pending")

    resp = await get(app, f"/verify/state?d={code.display_handle}", SAME_ORIGIN)

    assert resp.status_code == 200
    assert_state_headers(resp)
    body = resp.json()
    assert set(body) == {"status", "app_link"}
    assert body["status"] == "pending"
    link = urlsplit(body["app_link"])
    assert f"{link.scheme}://{link.netloc}{link.path}" == "https://app.postern.internal/pair"
    query = parse_qs(link.query)
    assert query["user_code"] == [code.user_code]
    verdict = verify_token(code.qr_secret, code.user_code, query["qr"][0], slot_at(time.time()))
    assert verdict is QrVerdict.VALID


async def test_the_app_link_changes_from_one_slot_to_the_next(
    app: Starlette, monkeypatch: pytest.MonkeyPatch
) -> None:
    code = await pairing(app, "pending")
    url = f"/verify/state?d={code.display_handle}"

    monkeypatch.setattr(verify_page, "_now", lambda: 1_790_000_000.0)
    first = (await get(app, url, SAME_ORIGIN)).json()["app_link"]
    monkeypatch.setattr(verify_page, "_now", lambda: 1_790_000_002.0)
    second = (await get(app, url, SAME_ORIGIN)).json()["app_link"]

    assert first != second
    assert parse_qs(urlsplit(first).query)["qr"][0].startswith("895000000.")
    assert parse_qs(urlsplit(second).query)["qr"][0].startswith("895000001.")


async def test_a_scanned_state_says_scanned_and_nothing_else(app: Starlette) -> None:
    code = await pairing(app, "scanned")

    resp = await get(app, f"/verify/state?d={code.display_handle}", SAME_ORIGIN)

    assert resp.status_code == 200
    assert_state_headers(resp)
    assert resp.json() == {"status": "scanned"}


async def test_every_closed_state_is_the_same_404(app: Starlette) -> None:
    answers = [
        await get(app, f"/verify/state?d={await handle_for(app, s)}", SAME_ORIGIN)
        for s in CLOSED_STATES
    ]

    assert [r.status_code for r in answers] == [404, 404, 404]
    assert answers[0].json() == answers[1].json() == answers[2].json() == {"status": "closed"}
    for resp in answers:
        assert_state_headers(resp)


# ---------------------------------------------------------------------------
# GET /verify/qr.svg
# ---------------------------------------------------------------------------


def assert_qr_headers(resp: httpx2.Response) -> None:
    assert resp.headers["cache-control"] == "no-store"
    assert resp.headers["x-content-type-options"] == "nosniff"
    assert resp.headers["content-security-policy"] == "default-src 'none'"
    assert resp.headers["cross-origin-resource-policy"] == "same-origin"


async def test_a_pending_pairing_gets_an_svg(app: Starlette) -> None:
    code = await pairing(app, "pending")

    resp = await get(app, f"/verify/qr.svg?d={code.display_handle}", SAME_ORIGIN)

    assert resp.status_code == 200
    assert resp.headers["content-type"] == "image/svg+xml"
    assert_qr_headers(resp)
    assert resp.content.startswith(b"<svg")
    assert code.user_code.encode() not in resp.content, "the SVG is path data, not text"


async def test_the_qr_encodes_the_app_link_for_the_current_slot(
    app: Starlette, monkeypatch: pytest.MonkeyPatch
) -> None:
    code = await pairing(app, "pending")
    drawn: list[str] = []
    real = verify_page.render_qr_svg

    def spy(link: str) -> bytes:
        drawn.append(link)
        return real(link)

    monkeypatch.setattr(verify_page, "render_qr_svg", spy)
    monkeypatch.setattr(verify_page, "_now", lambda: 1_790_000_000.0)

    await get(app, f"/verify/qr.svg?d={code.display_handle}", SAME_ORIGIN)
    state = (await get(app, f"/verify/state?d={code.display_handle}", SAME_ORIGIN)).json()

    assert drawn == [state["app_link"]]


@pytest.mark.parametrize("state", ["scanned", *CLOSED_STATES])
async def test_every_other_state_gets_the_same_empty_404(app: Starlette, state: str) -> None:
    resp = await get(app, f"/verify/qr.svg?d={await handle_for(app, state)}", SAME_ORIGIN)

    assert resp.status_code == 404
    assert resp.content == b""
    assert_qr_headers(resp)


# ---------------------------------------------------------------------------
# The hotlink refusal, on the image and the state.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "headers",
    [
        pytest.param({"Sec-Fetch-Site": "cross-site"}, id="cross-site"),
        pytest.param({"Sec-Fetch-Site": "same-site"}, id="same-site"),
        pytest.param({"Sec-Fetch-Site": "none"}, id="none"),
        pytest.param({}, id="no header at all"),
    ],
)
async def test_anything_but_same_origin_gets_the_closed_answer(
    app: Starlette, headers: dict[str, str]
) -> None:
    code = await pairing(app, "pending")

    image = await get(app, f"/verify/qr.svg?d={code.display_handle}", headers)
    state = await get(app, f"/verify/state?d={code.display_handle}", headers)

    assert image.status_code == 404
    assert image.content == b""
    assert_qr_headers(image)
    assert state.status_code == 404
    assert state.json() == {"status": "closed"}
    assert_state_headers(state)


async def test_the_page_itself_is_not_refused_for_a_cross_site_navigation(
    app: Starlette,
) -> None:
    """The page is opened from a link in the AI client, which is exactly a
    cross-site navigation; only the image and the state are refused."""
    code = await pairing(app, "pending")

    resp = await get(app, page_url(code.display_handle), {"Sec-Fetch-Site": "cross-site"})

    assert resp.status_code == 200
    assert code.user_code_display in resp.text


# ---------------------------------------------------------------------------
# GET /verify.js and /verify.css
# ---------------------------------------------------------------------------


async def test_the_script_is_served_as_javascript(app: Starlette) -> None:
    resp = await get(app, "/verify.js")

    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/javascript")
    assert resp.headers["x-content-type-options"] == "nosniff"
    assert "/verify/state?" in resp.text
    assert "30000" in resp.text, "the 429 back-off ceiling"


async def test_the_stylesheet_is_served_as_css(app: Starlette) -> None:
    resp = await get(app, "/verify.css")

    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/css")
    assert resp.headers["x-content-type-options"] == "nosniff"
```

2b. In `tests/test_confirm_auth.py`, replace `test_the_public_path_list_is_exactly_these_three` with:

```python
def test_the_public_path_list_is_exactly_these_eight() -> None:
    """Adding a ninth must be a deliberate, reviewed act.

    ``PUBLIC_PATHS`` is the single exemption list for the whole service. A
    change to it is a change to what the write path serves anonymously, and it
    should never happen as a side effect of some other edit. The five
    ``/verify`` entries are the browser's pairing page, and
    ``dev-docs/decisions/0021-public-html-on-the-write-key-service.md`` is
    where serving them here was decided.
    """
    assert PUBLIC_PATHS == {
        "/.well-known/jwks.json",
        "/device_authorization",
        "/token",
        "/verify",
        "/verify/qr.svg",
        "/verify/state",
        "/verify.js",
        "/verify.css",
    }


def test_every_public_path_is_a_route_with_methods(app: Starlette) -> None:
    """A public path the route table does not serve with ``.methods`` would be
    skipped by the table-driven tests above, which is how a ``StaticFiles``
    mount would have slipped past both of them."""
    served = {path for _, path in _routes(app)}
    assert set(PUBLIC_PATHS) <= served, set(PUBLIC_PATHS) - served
```

2c. In `tests/test_confirm_body_limit.py`, `test_every_route_is_covered_including_the_public_and_form_encoded_ones`: the parameter list becomes

```python
@pytest.mark.parametrize(
    ("path", "content_type"),
    [
        ("/token", "application/x-www-form-urlencoded"),
        ("/device_authorization", "application/json"),
        ("/approve", "application/json"),
        ("/scan", "application/json"),
        (PROTECTED, "application/json"),
        ("/.well-known/jwks.json", "application/json"),
        ("/verify", "text/plain"),
        ("/verify/qr.svg", "text/plain"),
        ("/verify/state", "text/plain"),
        ("/verify.js", "text/plain"),
        ("/verify.css", "text/plain"),
    ],
)
```

the docstring's last paragraph becomes

```
    The JWKS route and the five pairing-page routes are GETs that read no
    body, and are here because the limit covers every method. A route added
    to this service tomorrow is bounded by omission, the same direction
    ``PUBLIC_PATHS`` points for authentication.
```

and the method expression in the request becomes `"GET" if path.endswith("jwks.json") or path.startswith("/verify") else "POST",`.

- [ ] **Step 3: Run them to verify they fail**

Run: `uv run pytest tests/test_verify_page.py -q`
Expected: collection error, `ImportError: cannot import name 'verify_page' from 'services.confirm'`.

Run: `uv run pytest tests/test_confirm_auth.py tests/test_confirm_body_limit.py -q`
Expected: FAIL in `test_the_public_path_list_is_exactly_these_eight` only, on the set comparison. The six new body-limit cases already pass, because `BodySizeLimit` answers 413 before authentication and routing; they are there to keep the new paths covered if that order ever changes.

- [ ] **Step 4: Create the static files**

Create `services/confirm/static/verify.js`:

```javascript
// The pairing page's only script. Served same-origin from /verify.js so the
// page's Content-Security-Policy needs no inline script.
//
// Every two seconds it asks /verify/state what the pairing is doing, and acts
// on the answer exactly as the page-state table in dev-docs/qr-page-spec.md
// section 4 says:
//   pending -> point the app link at the current token and reload the QR
//   scanned -> remove the QR and the app link, keep the code, keep polling
//   404     -> stop, remove the code, the QR and the link, say it is closed
//   429     -> back off, doubling from 2 s to at most 30 s, until the next 200
// fetch() of a same-origin URL sends Sec-Fetch-Site: same-origin, which is
// what the state endpoint and the image require.
(function () {
  "use strict";

  var BASE_DELAY_MS = 2000;
  var MAX_DELAY_MS = 30000;
  var CLOSED_TEXT = "This pairing is closed. Return to your AI client.";
  var SCANNED_TEXT = "Compare the code in your app with this one.";

  var handle = document.body.getAttribute("data-handle");
  if (!handle) {
    return;
  }
  var query = "d=" + encodeURIComponent(handle);
  var delay = BASE_DELAY_MS;
  var stopped = false;

  function byId(id) {
    return document.getElementById(id);
  }

  function remove(id) {
    var element = byId(id);
    if (element && element.parentNode) {
      element.parentNode.removeChild(element);
    }
  }

  function say(text) {
    var instruction = byId("instruction");
    if (instruction) {
      instruction.textContent = text;
    }
  }

  function showPending(appLink) {
    var link = byId("app-link");
    if (link && typeof appLink === "string") {
      link.setAttribute("href", appLink);
    }
    var qr = byId("qr");
    if (qr) {
      qr.setAttribute("src", "/verify/qr.svg?" + query + "&t=" + Date.now());
    }
  }

  function showScanned() {
    remove("qr");
    remove("app-link");
    say(SCANNED_TEXT);
  }

  function showClosed() {
    stopped = true;
    remove("qr");
    remove("app-link");
    remove("pairing-code");
    say(CLOSED_TEXT);
  }

  function poll() {
    fetch("/verify/state?" + query, { cache: "no-store", credentials: "same-origin" })
      .then(function (response) {
        if (response.status === 404) {
          showClosed();
          return null;
        }
        if (response.status === 429) {
          delay = Math.min(delay * 2, MAX_DELAY_MS);
          return null;
        }
        if (response.status !== 200) {
          return null;
        }
        delay = BASE_DELAY_MS;
        return response.json();
      })
      .then(function (body) {
        if (!body) {
          return;
        }
        if (body.status === "pending") {
          showPending(body.app_link);
        } else if (body.status === "scanned") {
          showScanned();
        }
      })
      .catch(function () {
        // A network error is neither a 404 nor a 429: keep the current delay
        // and try again.
      })
      .then(function () {
        if (!stopped) {
          window.setTimeout(poll, delay);
        }
      });
  }

  window.setTimeout(poll, delay);
})();
```

Create `services/confirm/static/verify.css`:

```css
/* The pairing page's only stylesheet, served same-origin from /verify.css so
   the page's `style-src 'self'` has a target and no inline style is needed. */

:root {
  color-scheme: light dark;
}

body {
  margin: 0;
  font-family: system-ui, -apple-system, "Segoe UI", sans-serif;
  line-height: 1.5;
  background: #ffffff;
  color: #111111;
}

main {
  max-width: 28rem;
  margin: 0 auto;
  padding: 2rem 1rem;
  text-align: center;
}

h1 {
  font-size: 1.25rem;
  margin: 0 0 1.5rem;
}

.pairing-code {
  font-family: ui-monospace, "SFMono-Regular", Menlo, monospace;
  font-size: 2.5rem;
  letter-spacing: 0.2em;
  margin: 0 0 1.5rem;
}

#qr {
  display: block;
  width: 246px;
  height: 246px;
  max-width: 100%;
  margin: 0 auto 1.5rem;
}

#app-link {
  display: inline-block;
  margin: 0 0 1.5rem;
  padding: 0.75rem 1.25rem;
  border: 1px solid currentColor;
  border-radius: 0.5rem;
  color: inherit;
  text-decoration: none;
}

#instruction {
  margin: 0;
}

@media (prefers-color-scheme: dark) {
  body {
    background: #111111;
    color: #f2f2f2;
  }
}
```

The Dockerfile's confirm stage copies `/app/services/confirm` whole, so both files ship in the confirm image with no Dockerfile change.

- [ ] **Step 5: Create the routes**

Create `services/confirm/verify_page.py`:

```python
"""The browser half of the device grant: the pairing page, its QR and its state.

Five public GET routes, and the only HTML this repository serves:

- ``/verify?d=<handle>`` -- the page the AI client's user opens from
  ``verification_uri_complete``.
- ``/verify/qr.svg?d=<handle>`` -- the QR the page embeds, drawn by ``segno``
  from the app link with the current slot's rotation token.
- ``/verify/state?d=<handle>`` -- what the page's script polls every two
  seconds.
- ``/verify.js`` and ``/verify.css`` -- the page's only script and only
  stylesheet, served same-origin so the CSP needs no inline anything.

``dev-docs/qr-page-spec.md`` section 4 is the contract, and
``dev-docs/decisions/0021-public-html-on-the-write-key-service.md`` is why
these live on the service that holds the write key.

THE PAGE RENDERS STORED VALUES ONLY. The handle in the query string is a
lookup key and nothing else: what the page, the image and the state show is
the ``display_handle`` and the ``user_code`` read from the row the lookup
returned, so a crafted ``d`` can change which pairing is found and never what
is written into the markup.

THREE STATES, AND THE CLOSED ONE HAS NO SUBSTATES. Pending (unexpired,
unscanned), scanned (unexpired, scanned, unapproved), closed (unknown handle,
expired, or approved whether or not exchanged). An unknown, an expired and an
approved pairing are indistinguishable on every route, so nothing here
confirms that an approval happened.

THE HOTLINK REFUSAL. ``qr.svg`` and ``/verify/state`` answer the closed 404
to any request whose ``Sec-Fetch-Site`` is not exactly ``same-origin``,
including one with no such header, and both carry
``Cross-Origin-Resource-Policy: same-origin`` as a second, independent
refusal. Without it an ``<img>`` pointing here from an email or a forum post
would draw a fresh QR on every open and defeat rotation outright. What it
does not stop -- a server-side relay fetching the image for the attacker's
own pairing -- is in the spec's "What this does not fix".

NO ``audit_log`` ROW ON ANY OF THE FIVE, by ``PairingAudit``'s rule: none of
them resolves an identity, and a row per poll would be an unauthenticated
INSERT every two seconds per open tab.
"""

from __future__ import annotations

import html
import io
import time
from pathlib import Path
from typing import Literal
from urllib.parse import quote, urlencode

import segno
from postern_core.auth.device_codes import DeviceCode, DeviceCodeStoreBase
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, Response
from starlette.routing import Route

from services.confirm.qr_token import slot_at, token_for
from services.confirm.settings import ConfirmSettings

PairingState = Literal["pending", "scanned", "closed"]

#: The instruction under the pairing code, per state. Pending asks the user to
#: check the origin of the pairing as well as the code, because the page URL
#: itself can be the lure (the spec's "What this does not fix").
PENDING_TEXT = (
    "Check that the code in your app matches this one, and only continue if you "
    "started this on your own computer just now."
)
SCANNED_TEXT = "Compare the code in your app with this one."
CLOSED_TEXT = "This pairing is closed. Return to your AI client."
#: What a bare ``/verify`` says. There is no form to type a code into: that
#: form would be the ``user_code`` enumeration oracle the handle exists to
#: avoid.
NO_HANDLE_TEXT = "Open the full link your AI client printed."

#: The noscript refresh, in seconds, on a pending or scanned page. Five and
#: not one: one fails WCAG 2.2.1 and 2.2.2 and spends 60 requests a minute.
REFRESH_SECONDS = 5

#: Longer than any handle this service issues (22 characters). A longer value
#: names nothing, so it is answered as closed without a store round trip.
MAX_HANDLE_LENGTH = 64

PAGE_CSP = (
    "default-src 'none'; img-src 'self'; script-src 'self'; style-src 'self'; "
    "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
)

#: Every header the page carries, in every state.
PAGE_HEADERS = {
    "Content-Security-Policy": PAGE_CSP,
    # The handle is in the URL, and the page's own requests must not carry it
    # off-origin in a Referer.
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    "Strict-Transport-Security": "max-age=31536000",
    # For browsers that predate `frame-ancestors`.
    "X-Frame-Options": "DENY",
}

#: The state endpoint's headers, on every answer including the 404.
STATE_HEADERS = {
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    "Cross-Origin-Resource-Policy": "same-origin",
}

#: The image's headers, on every answer including the 404. The CSP is there
#: because an SVG opened directly is a document.
QR_HEADERS = {**STATE_HEADERS, "Content-Security-Policy": "default-src 'none'"}

#: The script's and the stylesheet's.
ASSET_HEADERS = {"X-Content-Type-Options": "nosniff"}

_STATIC = Path(__file__).resolve().parent / "static"
VERIFY_JS = (_STATIC / "verify.js").read_bytes()
VERIFY_CSS = (_STATIC / "verify.css").read_bytes()


def _now() -> float:
    """The clock the rotation token is cut from. A function so a test can
    move it across a slot boundary."""
    return time.time()


def pairing_state(code: DeviceCode | None) -> PairingState:
    """Which of the three states a looked-up row is in."""
    if code is None or code.is_expired or code.approved:
        return "closed"
    if code.scanned_by:
        return "scanned"
    return "pending"


def app_link(settings: ConfirmSettings, code: DeviceCode, now: float) -> str:
    """The app link for ``code`` with the rotation token for ``now``'s slot.

    ``{device_app_link_uri}?user_code=<user_code>&qr=<slot>.<mac>``. The
    ``user_code`` is the stored six-character form; the token is
    ``services/confirm/qr_token.py``'s, keyed by the row's own secret.
    """
    token = token_for(code.qr_secret, code.user_code, slot_at(now))
    separator = "&" if "?" in settings.device_app_link_uri else "?"
    query = urlencode({"user_code": code.user_code, "qr": token})
    return f"{settings.device_app_link_uri}{separator}{query}"


def render_qr_svg(link: str) -> bytes:
    """The QR for ``link`` as an SVG document, with no XML declaration.

    ``segno`` 1.6.6's ``make_qr`` and ``save(kind="svg")``. The output holds
    path data and nothing of the encoded text.
    """
    qr = segno.make_qr(link, error="m")
    buffer = io.BytesIO()
    qr.save(buffer, kind="svg", scale=6, border=4, dark="#000", light="#fff", xmldecl=False)
    return buffer.getvalue()


def render_page(state: PairingState | None, code: DeviceCode | None, link: str | None) -> str:
    """The page's HTML. ``state`` ``None`` is a bare ``/verify`` with no handle.

    Every interpolated value is ``html.escape``-d, including the ones that
    come from the store and could not carry markup today, so that stays true
    if the alphabet or the handle format ever changes.
    """
    live = state in ("pending", "scanned") and code is not None
    head_extra = ""
    body_attributes = ""
    parts: list[str] = []
    if live and code is not None:
        head_extra = (
            f'<noscript><meta http-equiv="refresh" content="{REFRESH_SECONDS}"></noscript>\n'
            '<script src="/verify.js" defer></script>\n'
        )
        body_attributes = f' data-handle="{html.escape(code.display_handle, quote=True)}"'
        parts.append(
            f'<p id="pairing-code" class="pairing-code">{html.escape(code.user_code_display)}</p>'
        )
        if state == "pending" and link is not None:
            image_src = f"/verify/qr.svg?d={quote(code.display_handle, safe='')}"
            parts.append(
                f'<img id="qr" src="{html.escape(image_src, quote=True)}" '
                'alt="QR code to scan with your bank app" width="246" height="246">'
            )
            parts.append(
                f'<a id="app-link" href="{html.escape(link, quote=True)}">Open in your bank app</a>'
            )
            parts.append(f'<p id="instruction">{html.escape(PENDING_TEXT)}</p>')
        else:
            parts.append(f'<p id="instruction">{html.escape(SCANNED_TEXT)}</p>')
    elif state is None:
        parts.append(f'<p id="instruction">{html.escape(NO_HANDLE_TEXT)}</p>')
    else:
        parts.append(f'<p id="instruction">{html.escape(CLOSED_TEXT)}</p>')
    body = "\n".join(parts)
    return (
        "<!doctype html>\n"
        '<html lang="en">\n'
        "<head>\n"
        '<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        "<title>Pair your AI client</title>\n"
        '<link rel="stylesheet" href="/verify.css">\n'
        f"{head_extra}"
        "</head>\n"
        f"<body{body_attributes}>\n"
        "<main>\n"
        "<h1>Pair your AI client</h1>\n"
        f"{body}\n"
        "</main>\n"
        "</body>\n"
        "</html>\n"
    )


async def _lookup(request: Request) -> DeviceCode | None:
    """The row the ``d`` parameter names, or ``None``. Expired rows come back
    ``None`` from the store's lookup already."""
    handle = request.query_params.get("d", "")
    if not handle or len(handle) > MAX_HANDLE_LENGTH:
        return None
    store: DeviceCodeStoreBase = request.app.state.device_code_store
    return await store.get_by_display_handle(handle)


def _same_origin(request: Request) -> bool:
    """Exactly ``Sec-Fetch-Site: same-origin``. Anything else -- another
    value, or no header at all -- is refused."""
    return request.headers.get("sec-fetch-site") == "same-origin"


def _closed_state() -> JSONResponse:
    """The one answer for every closed pairing and every refused fetch."""
    return JSONResponse({"status": "closed"}, status_code=404, headers=STATE_HEADERS)


def _no_qr() -> Response:
    """The one 404 the image answers, for every state but pending and every
    refused fetch. Empty, with the image's headers."""
    return Response(status_code=404, headers=QR_HEADERS)


async def verify_page(request: Request) -> HTMLResponse:
    """``GET /verify``: 200 in every state, rendered from the stored row."""
    if not request.query_params.get("d"):
        return HTMLResponse(render_page(None, None, None), headers=PAGE_HEADERS)
    code = await _lookup(request)
    state = pairing_state(code)
    if state == "closed" or code is None:
        return HTMLResponse(render_page("closed", None, None), headers=PAGE_HEADERS)
    link = None
    if state == "pending":
        settings: ConfirmSettings = request.app.state.settings
        link = app_link(settings, code, _now())
    return HTMLResponse(render_page(state, code, link), headers=PAGE_HEADERS)


async def verify_state(request: Request) -> JSONResponse:
    """``GET /verify/state``: pending with the current app link, scanned, or 404."""
    if not _same_origin(request):
        return _closed_state()
    code = await _lookup(request)
    state = pairing_state(code)
    if state == "closed" or code is None:
        return _closed_state()
    if state == "scanned":
        return JSONResponse({"status": "scanned"}, headers=STATE_HEADERS)
    settings: ConfirmSettings = request.app.state.settings
    return JSONResponse(
        {"status": "pending", "app_link": app_link(settings, code, _now())},
        headers=STATE_HEADERS,
    )


async def verify_qr(request: Request) -> Response:
    """``GET /verify/qr.svg``: the QR while pending, 404 otherwise."""
    if not _same_origin(request):
        return _no_qr()
    code = await _lookup(request)
    if code is None or pairing_state(code) != "pending":
        return _no_qr()
    settings: ConfirmSettings = request.app.state.settings
    svg = render_qr_svg(app_link(settings, code, _now()))
    return Response(svg, media_type="image/svg+xml", headers=QR_HEADERS)


async def verify_js(request: Request) -> Response:
    """``GET /verify.js``, the page's only script."""
    return Response(VERIFY_JS, media_type="text/javascript", headers=ASSET_HEADERS)


async def verify_css(request: Request) -> Response:
    """``GET /verify.css``, the page's only stylesheet."""
    return Response(VERIFY_CSS, media_type="text/css", headers=ASSET_HEADERS)


def verify_page_routes() -> list[Route]:
    """The five public routes, each a plain ``Route``.

    NOT A ``StaticFiles`` MOUNT, even for the script and the stylesheet.
    ``AppAssertionMiddleware`` matches ``PUBLIC_PATHS`` exactly, and
    ``tests/test_confirm_auth.py``'s route-table test skips anything without
    ``.methods``, so a mount would slip past both.
    """
    return [
        Route("/verify", verify_page, methods=["GET"]),
        Route("/verify/qr.svg", verify_qr, methods=["GET"]),
        Route("/verify/state", verify_state, methods=["GET"]),
        Route("/verify.js", verify_js, methods=["GET"]),
        Route("/verify.css", verify_css, methods=["GET"]),
    ]
```

- [ ] **Step 6: Make them public, in `services/confirm/auth.py`**

Replace `PUBLIC_PATHS` with the following, which keeps the three existing reasons above it and adds the five new ones below them:

```python
#: THE FIVE BELOW ARE THE PAIRING PAGE, added 2026-09-30, and all five are
#: the BROWSER again: it opened ``verification_uri_complete`` and holds no
#: assertion. None sets a cookie or reads one, and every other path on this
#: service authenticates with a bearer assertion and never a cookie, so a
#: page served here has no ambient credential to borrow.
#: ``dev-docs/decisions/0021-public-html-on-the-write-key-service.md`` is why
#: this service and not ``services/api`` serves them.
#:
#: ``/verify``
#:     The page a browser opens from ``verification_uri_complete``; the
#:     browser holds no assertion. It shows only what the stored row says.
#:
#: ``/verify/qr.svg``
#:     The image the page embeds. Refused unless ``Sec-Fetch-Site`` is
#:     ``same-origin``, so another site cannot embed it.
#:
#: ``/verify/state``
#:     The status the page's script polls, refused the same way.
#:
#: ``/verify.js``
#:     The page's only script, same-origin so the page's CSP needs no inline
#:     script.
#:
#: ``/verify.css``
#:     The page's only stylesheet, so ``style-src 'self'`` has a target.
PUBLIC_PATHS = frozenset(
    {
        "/.well-known/jwks.json",
        "/device_authorization",
        "/token",
        "/verify",
        "/verify/qr.svg",
        "/verify/state",
        "/verify.js",
        "/verify.css",
    }
)
```

(the snippet starts with the new comment block; insert it after the existing `#:     exact code on their own phone.` line, and it ends with the whole new `PUBLIC_PATHS = frozenset(...)` assignment, which replaces the old one).

- [ ] **Step 7: Wire them, in `services/confirm/main.py`**

Add `from services.confirm.verify_page import verify_page_routes` directly after `from services.confirm.settings import ConfirmSettings`. In `create_confirm_app`'s route list, add `+ verify_page_routes()` between the `device_auth_routes(...)` term and `+ callback_routes()`. In the module docstring, replace

```
Everything except ``/.well-known/jwks.json``, ``/device_authorization`` and
``/token`` requires a verified banking-app assertion. ``services/confirm/auth.py``
holds that middleware, the reasoning for each public path, and the audience
requirement an operator owns.
```

with

```
Everything except ``/.well-known/jwks.json``, ``/device_authorization``,
``/token`` and the five routes of the browser's pairing page (``/verify``,
``/verify/qr.svg``, ``/verify/state``, ``/verify.js``, ``/verify.css``)
requires a verified banking-app assertion. ``services/confirm/auth.py`` holds
that middleware, the reasoning for each public path, and the audience
requirement an operator owns.
```

and add to the device authorization endpoint list, directly above the `POST /scan` item Task 9 added:

```
- ``GET /verify``, ``/verify/qr.svg``, ``/verify/state``, ``/verify.js``,
  ``/verify.css`` -- the browser's pairing page, its QR, its state, its script
  and its stylesheet (``services.confirm.verify_page``).
```

- [ ] **Step 8: Recount the public paths, in `services/confirm/customer_rate_limit.py`**

In the comment above `FALLBACK_CUSTOMER_LIMIT`, `three entries in` becomes `eight entries in`. In `CustomerRateLimit.__call__`'s comment, the three occurrences of `three` in

```
            # exactly the three entries in its ``PUBLIC_PATHS`` -- and those
            # three have no customer at the moment they are served, which is
            # the premise of the device grant rather than an oversight. They
            # are the outer address-keyed limiter's alone, and it limits all
            # three. Any other route reaching here unverified would already
```

become `eight`.

- [ ] **Step 9: Run the tests to verify they pass**

Run: `uv run pytest tests/test_verify_page.py tests/test_confirm_auth.py tests/test_confirm_body_limit.py tests/test_confirm_rate_limit.py tests/test_confirm_customer_rate_limit.py tests/test_zt8_no_hardcoded_external_endpoints.py -q`
Expected: all pass.

- [ ] **Step 10: Format, then run the gate**

Run: `uv run ruff format packages services tests && make ci`
Expected: exit 0 (`lock` included: `uv lock --check --offline` accepts the lock `uv add` wrote).

- [ ] **Step 11: Commit**

```bash
git add pyproject.toml uv.lock services/confirm/verify_page.py services/confirm/static/verify.js services/confirm/static/verify.css services/confirm/auth.py services/confirm/main.py services/confirm/customer_rate_limit.py tests/test_verify_page.py tests/test_confirm_auth.py tests/test_confirm_body_limit.py
git commit -m "feat(confirm): serve the pairing page, its rotating QR and its state" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 11: The whole flow, end to end over ASGI

Spec, Testing, last bullet: `device_authorization` → `/verify` → `/verify/state` → `qr.svg` → `/scan` → `/approve` → `/token` returns a read token, with `/verify/state` reading `scanned` after the scan and `404` after the approval.

This test drives code Tasks 1 to 10 already built, so there is no red step that could fail for the right reason: it is a regression net over the whole chain, and if it fails the assertion that fails names the broken link.

**Files:**
- Create: `tests/test_qr_pairing_end_to_end.py`

- [ ] **Step 1: Write the test**

Create `tests/test_qr_pairing_end_to_end.py`:

```python
"""The whole QR pairing, as a browser and a phone drive it, over ASGI.

``POST /device_authorization`` -> ``GET /verify`` -> ``GET /verify/state`` ->
``GET /verify/qr.svg`` -> ``POST /scan`` -> ``POST /approve`` ->
``POST /token``, with the state endpoint read after the scan and after the
approval. Nothing is handed to the phone that it could not have read off the
QR: the ``user_code`` and the rotation token come out of the ``app_link`` the
state endpoint serves, which is the string the QR encodes, and the
``device_code`` never leaves the browser.

The audit trail is read back at the end: one row each for the scan, the
approval and the mint, joined on the device code's handle.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from dataclasses import replace
from urllib.parse import parse_qs, urlsplit

import httpx2
import pytest
from fastmcp.server.auth.providers.jwt import JWTVerifier, RSAKeyPair
from joserfc import jwt as joserfc_jwt
from joserfc.jwk import KeySet
from postern_core.auth.device_keys import no_enrolled_devices
from postern_core.store.engine import Database
from postern_core.store.models import OUTCOME_RETURNED, AuditEntry
from sqlalchemy import select
from starlette.applications import Starlette

from services.confirm.audit import PAIRING_TOOL_NAME, SCAN_TOOL_NAME, TOKEN_TOOL_NAME
from services.confirm.main import create_confirm_app
from services.confirm.settings import ConfirmSettings
from tests.fixtures.append_only_bypass import (
    delete_audit_rows_by_bypassing_the_append_only_triggers,
)

ISSUER = "https://app.test.invalid"
AUDIENCE = "postern-confirm"
CUSTOMER = "cust_7f3a"
SAME_ORIGIN = {"Sec-Fetch-Site": "same-origin"}


async def _wipe(db: Database) -> None:
    async with db.sessionmaker() as s:
        await delete_audit_rows_by_bypassing_the_append_only_triggers(s)
        await s.commit()


@pytest.fixture()
async def clean(database: Database) -> AsyncIterator[Database]:
    await _wipe(database)
    yield database
    await _wipe(database)


@pytest.fixture()
def app(pg_url: str) -> tuple[Starlette, RSAKeyPair]:
    key_pair = RSAKeyPair.generate()
    verifier = JWTVerifier(public_key=key_pair.public_key, issuer=ISSUER, audience=AUDIENCE)
    built = create_confirm_app(
        replace(ConfirmSettings.for_testing(), database_url=pg_url),
        assertion_verifier=verifier,
        device_key_store=no_enrolled_devices(),
    )
    return built, key_pair


async def test_a_browser_and_a_phone_complete_a_pairing_through_every_route(
    app: tuple[Starlette, RSAKeyPair], clean: Database
) -> None:
    confirm, key_pair = app
    assertion = key_pair.create_token(subject=CUSTOMER, issuer=ISSUER, audience=AUDIENCE)
    phone_headers = {"Authorization": f"Bearer {assertion}"}
    transport = httpx2.ASGITransport(app=confirm)

    async with (
        httpx2.AsyncClient(transport=transport, base_url="https://auth.test") as browser,
        httpx2.AsyncClient(transport=transport, base_url="https://auth.test") as phone,
    ):
        started = await browser.post("/device_authorization", json={"client_id": "claude-code"})
        assert started.status_code == 200, started.text
        grant = started.json()
        handle = parse_qs(urlsplit(grant["verification_uri_complete"]).query)["d"][0]

        page = await browser.get("/verify", params={"d": handle})
        assert page.status_code == 200
        assert grant["user_code"] in page.text

        pending = await browser.get("/verify/state", params={"d": handle}, headers=SAME_ORIGIN)
        assert pending.json()["status"] == "pending"
        qr = await browser.get("/verify/qr.svg", params={"d": handle}, headers=SAME_ORIGIN)
        assert qr.status_code == 200
        assert qr.content.startswith(b"<svg")

        # What the phone's camera reads: the app link, and nothing else.
        link = parse_qs(urlsplit(pending.json()["app_link"]).query)
        assert grant["device_code"] not in pending.json()["app_link"]
        scanned = await phone.post(
            "/scan",
            json={"user_code": link["user_code"][0], "qr": link["qr"][0]},
            headers=phone_headers,
        )
        assert scanned.status_code == 200, scanned.text
        assert scanned.json()["user_code"] == grant["user_code"]
        assert scanned.json()["client_id"] == "claude-code"
        assert scanned.json()["client_id_verified"] is False

        after_scan = await browser.get("/verify/state", params={"d": handle}, headers=SAME_ORIGIN)
        assert after_scan.json() == {"status": "scanned"}
        no_more_qr = await browser.get("/verify/qr.svg", params={"d": handle}, headers=SAME_ORIGIN)
        assert no_more_qr.status_code == 404

        approved = await phone.post(
            "/approve", json={"user_code": grant["user_code"]}, headers=phone_headers
        )
        assert approved.status_code == 200, approved.text

        after_approval = await browser.get(
            "/verify/state", params={"d": handle}, headers=SAME_ORIGIN
        )
        assert after_approval.status_code == 404

        token = await browser.post(
            "/token", data={"grant_type": "device_code", "device_code": grant["device_code"]}
        )

    assert token.status_code == 200, token.text
    claims = joserfc_jwt.decode(
        token.json()["access_token"],
        KeySet.import_key_set(confirm.state.postern_read_key_source.public_jwks()),
        algorithms=["RS256"],
    ).claims
    assert claims["sub"] == CUSTOMER

    async with clean.sessionmaker() as s:
        written = list((await s.execute(select(AuditEntry).order_by(AuditEntry.id))).scalars())
    assert [(r.tool_name, r.outcome, r.detail) for r in written] == [
        (SCAN_TOOL_NAME, OUTCOME_RETURNED, None),
        (PAIRING_TOOL_NAME, OUTCOME_RETURNED, None),
        (TOKEN_TOOL_NAME, OUTCOME_RETURNED, None),
    ]
    assert len({r.arguments["device_code_handle"] for r in written}) == 1
```

- [ ] **Step 2: Run it**

Run: `uv run pytest tests/test_qr_pairing_end_to_end.py -q`
Expected: 1 passed. If it fails, fix the task that owns the failing link; do not loosen an assertion.

- [ ] **Step 3: Format, then run the gate**

Run: `uv run ruff format packages services tests && make ci`
Expected: exit 0.

- [ ] **Step 4: Commit**

```bash
git add tests/test_qr_pairing_end_to_end.py
git commit -m "test(confirm): drive the whole QR pairing end to end" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 12: Decision record 0021, and the four documents the spec names as stale

Spec section 3's last paragraph (decision record 0021) and the Testing section's list of documents that describe removed symbols or settings. `make citations` checks only anchored citations, so nothing but this task catches these. `CLAUDE.md`, and the new variables in `docs/user-guide/getting-started.md`, are Task 13's.

**Files:**
- Create: `dev-docs/decisions/0021-public-html-on-the-write-key-service.md`
- Modify: `docs/user-guide/getting-started.md`
- Modify: `docs/user-guide/components/confirm-service.md`
- Modify: `docs/user-guide/components/session-store.md`
- Modify: `dev-docs/decisions/0012-device-code-single-use.md`

There is no failing test to write for documentation. The check is Step 6's grep, which prints the stale references before this task and must print none after it.

- [ ] **Step 1: Write the decision record**

Create `dev-docs/decisions/0021-public-html-on-the-write-key-service.md`:

```markdown
# 0021. The pairing page is served by the service that holds the write key

Date: 30 September 2026

## Status

Accepted.

## Context

RFC 8628's browser needs a page: the one `verification_uri_complete` opens,
showing the pairing code and a QR the bank app scans. Handoff §7.3 requires it
and until this record nothing in the repository served any HTML at all.

The handoff's architecture table puts the device grant, and with it the QR
page, on `services/api`, the read path. The code does not: the grant lives in
`services/confirm`, because the grant mints the browser's read token and the
device-code store sits beside that mint (`ConfirmSettings`' docstring records
the read-key exception this already is). The page reads that same store on
every request -- by display handle, to draw the QR and answer the state poll --
so wherever the page is served, it needs the device-code store.

That makes the question concrete: five unauthenticated GET routes, one of them
HTML, on the one process that holds the WRITE signing key and reaches backend
write endpoints.

## Decision

Serve the page from `services/confirm`, as five plain Starlette routes added to
`services/confirm/auth.py::PUBLIC_PATHS` with a reason each: `/verify`,
`/verify/qr.svg`, `/verify/state`, `/verify.js`, `/verify.css`.
`dev-docs/qr-page-spec.md` section 4 is the contract.

It is acceptable here, and only because all of the following hold together:

- **No ambient credential exists on this origin.** Every other path authenticates
  with a bearer assertion the operator's app backend mints, checked by
  `AppAssertionMiddleware`; no path sets or reads a cookie. A page served here
  has nothing a cross-site request could borrow, so the usual reason to keep
  public HTML away from a privileged origin -- a script on it riding the
  origin's session -- has no session to ride.
- **No inline script and no third-party content.** The page's CSP is
  `default-src 'none'` with `'self'` only for the image, the one script, the one
  stylesheet and the state fetch, plus `frame-ancestors 'none'`,
  `base-uri 'none'` and `form-action 'none'`. The script and the stylesheet are
  two static files in the repository, served same-origin.
- **The page renders stored values only.** The `d` query parameter is a lookup
  key; the markup carries the `display_handle` and `user_code` read back from
  the row, escaped. A crafted URL can change which pairing is found and never
  what is written into the page.
- **Nothing on these routes reaches a key, a backend or the database.** They
  read the device-code store and draw an SVG. The write key is not in reach of
  any of their code paths, and they write no `audit_log` row.
- **The image and the state refuse other sites.** Both answer 404 unless
  `Sec-Fetch-Site` is exactly `same-origin`, and both carry
  `Cross-Origin-Resource-Policy: same-origin`.

## Alternatives rejected

**Serve the page from `services/api`.** That is where the handoff draws it, and
it would keep HTML off the write-key process. It needs the device-code store
there too, and there are two ways to get it. Move the whole grant to
`services/api`, which is a change of its own with its own review, out of scope
for a page. Or have `services/api` read the store `services/confirm` writes,
which puts one Redis keyspace under two deployables with nothing in the tree
saying which one owns it, and makes every change to the pairing's row shape a
two-service release.

**A third deployable for the page.** Operationally the cleanest isolation, and
the most expensive: a new image, a new task definition, and a Redis-sharing
contract between it and `services/confirm` identical to the one just rejected.

**A `StaticFiles` mount for the script and stylesheet.** `AppAssertionMiddleware`
matches `PUBLIC_PATHS` exactly and `tests/test_confirm_auth.py`'s route-table
test skips any route without `.methods`, so a mount would slip past both
controls silently. Two plain routes cost nothing and stay inside both.

## What would change this decision

- **A cookie or any session on this origin.** The first line of "acceptable
  here" stops holding the day one exists, and the page must move off the
  write-key origin before that ships.
- **Anything on the page other than the stored pairing.** Account data, a form,
  a login, a third-party script or font: each widens what an HTML response on
  this origin can do.
- **The grant moving to `services/api`.** Then the page moves with it, and this
  record is superseded.

## Consequences

The confirm service now answers unauthenticated GETs with HTML, eight public
paths where there were three. Each is rate-limited per address bucket
(`services/confirm/rate_limit.py`), bounded by `BodySizeLimit`, and listed in
`PUBLIC_PATHS` with its reason, so the exemption list is still the single place
to read what the write path serves anonymously.

The page does not stop consent phishing: the URL itself can be the lure, and a
live relay can proxy the QR. `dev-docs/qr-page-spec.md`'s "What this does not
fix" is the record of that, and `creator_ip` is recorded on every pairing for
the later spec that will compare it with the scanner's network.
```

- [ ] **Step 2: `docs/user-guide/getting-started.md`**

In the "Confirm Service" table, delete the row that begins `| `POSTERN_USER_CODE_MAX_ATTEMPTS` | No | `3` |`. The unknown-variable startup check (`c3aa67c`) now refuses to start a confirm service whose environment still sets it, so an operator who kept it gets a startup refusal naming it, which is the intended way to learn it is gone.

- [ ] **Step 3: `docs/user-guide/components/confirm-service.md`**

Replace everything from the `### Endpoints` heading of the "Device Authorization" section down to (not including) the paragraph that begins `` `customer_ref` used to be `client_id`, reused for two purposes.`` with:

````markdown
### Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `POST` | `/device_authorization` | public | Generate device code + user_code (pairing code) |
| `POST` | `/token` | public | Exchange device code for a read token (polling; error until approved) |
| `GET` | `/verify` | public | The browser's pairing page: pairing code, QR, app link |
| `GET` | `/verify/qr.svg` | public, same-origin only | The QR the page embeds, rotated every two seconds |
| `GET` | `/verify/state` | public, same-origin only | What the page's script polls: pending, scanned, or 404 |
| `GET` | `/verify.js`, `/verify.css` | public | The page's only script and stylesheet |
| `POST` | `/scan` | **app assertion** | Banking app scan of the QR; the first customer to scan holds the pairing |
| `POST` | `/approve` | **app assertion** | Banking app approval callback, for the customer who scanned |

`/device_authorization`, `/token` and the five `/verify` routes are public
because the caller is the **browser**, which holds no credential — that is the
premise of RFC 8628, not an oversight. The `device_code` (43 characters from
`secrets.token_urlsafe(32)`) is the authority at `/token` and never appears in
the page, the QR or the page URL. All eight are listed in `PUBLIC_PATHS` in
[`services/confirm/auth.py`](../../../services/confirm/auth.py); every other
route on this service is denied by default. Decision record 0021 is why the page
is served here rather than by `services/api`.

### Flow

```
1. Browser → POST /device_authorization
   ← device_code + user_code (XXX-XXX) + verification_uri
     + verification_uri_complete = verification_uri?d=<display handle>

2. Browser opens verification_uri_complete (GET /verify?d=...)
   The page shows the pairing code and a QR encoding the app link:
     POSTERN_DEVICE_APP_LINK_URI?user_code=<code>&qr=<slot>.<mac>
   The QR's token rotates every two seconds.

3. Mobile app scans → POST /scan
     Authorization: Bearer <assertion from the operator's app backend>
     { "user_code": "ABC-DEF", "qr": "<slot>.<mac>" }
   ← 200 { client_id, client_id_verified: false, scopes, expires_at, user_code }

4. User compares the pairing codes and verifies identity → POST /approve
     Authorization: Bearer <assertion>
     { "user_code": "ABC-DEF" }
   ← 200 { "status": "approved" }
```

The customer is the assertion's verified `sub`. There is NO body field naming the
customer, and `/approve` refuses a body that still carries `device_code`
(`400 invalid_request`). A pairing can be approved only by the customer whose app
scanned it first; a second customer's scan of a pairing that has not been
exchanged revokes it (`400 scan_conflict`).

```
5. Browser → POST /token (grant_type=device_code, device_code=...)
   ← 400 authorization_pending (until approved)
   ← 200 { access_token, token_type, expires_in } (after approval)
```

`/scan` and `/approve` return **401** for a missing or unverifiable assertion and
**403** if the assertion's `sub` is not a `cust_...` reference or the customer is
revoked. Every refusal that could reveal whether a pairing exists -- unknown,
expired, unscanned, scanned by someone else, already approved, a forged rotation
token -- is the same **400** `invalid_grant`; `/scan` answers `qr_stale` for a
genuine token more than ten seconds old and `scan_conflict` as above. The
distinction lives in each request's `audit_log.detail`.

### Device Code Model (`packages/postern-core/src/postern_core/auth/device_codes.py`)

```python
@dataclass(frozen=True)
class DeviceCode:
    device_code: str          # Opaque 40+ char code (secrets.token_urlsafe(32))
    user_code: str            # 6-char alphanumeric pairing code (no ambiguous chars)
    verification_uri: str     # Base URI of the browser's pairing page
    expires_at: datetime      # UTC expiry (default 900s = 15 min)
    interval: int             # Seconds between token polls (default 5)
    client_id: str            # OAuth client ID, caller-supplied, NEVER an identity
    scopes: str               # Space-separated scope list
    approved: bool            # Whether mobile app has approved
    approved_at: datetime | None  # Approval timestamp
    customer_ref: str         # Verified assertion `sub`, empty until approved
    exchanged_at: datetime | None  # When /token spent it
    display_handle: str       # 128 random bits; keys the page, useless at /token
    qr_secret: bytes          # Per-pairing HMAC key for the QR's rotation token
    creator_ip: str | None    # Where /device_authorization came from
    scanned_by: str           # Customer whose app scanned first, empty until scanned
    scanned_at: datetime | None  # When
```
````

That block replaces the endpoint table (which lacked `/scan` and the five page routes), the flow (whose `/approve` body carried `device_code`), the attempt-budget sentence naming `POSTERN_USER_CODE_MAX_ATTEMPTS`, and the model listing `user_code_attempts`.

- [ ] **Step 4: `docs/user-guide/components/session-store.md`**

In the "Device Code Store" section, replace the code block that lists `DeviceCodeStoreBase`'s abstract methods (the one naming `approve_device_code` and `update_device_code`) with:

````markdown
```python
class DeviceCodeStoreBase(ABC):
    @abstractmethod
    async def create_device_code(self, *, client_id: str, scopes: str, ...) -> DeviceCode: ...
    @abstractmethod
    async def get_device_code(self, device_code: str) -> DeviceCode | None: ...
    @abstractmethod
    async def get_by_display_handle(self, display_handle: str) -> DeviceCode | None: ...
    @abstractmethod
    async def get_by_user_code(self, user_code: str) -> DeviceCode | None: ...
    @abstractmethod
    async def consume_device_code(self, device_code: str) -> bool: ...
    @abstractmethod
    async def claim_scan(self, device_code: str, customer_ref: str) -> ScanClaim: ...
    @abstractmethod
    async def approve_scanned(self, device_code: str, customer_ref: str) -> bool: ...
    @abstractmethod
    async def revoke_device_code(self, device_code: str) -> None: ...
```

There is no whole-row write. `consume_device_code`, `claim_scan` and
`approve_scanned` are compare-and-set operations -- `WATCH`/`MULTI` on Redis, no
`await` between read and write in memory -- because a snapshot read before one of
them and written back after it would silently undo it. The two lookups are
secondary keys created with `SET NX EX`, deleted on revoke and left in place by
consume.
````

The replacement ends with a new explanatory paragraph after the code block; the `Factory: ...` line that follows it is unchanged.

- [ ] **Step 5: `dev-docs/decisions/0012-device-code-single-use.md`**

Replace the bullet

```markdown
- **This repository already chose this trade twice.** A single mistyped pairing
  code at the attempt-budget floor revokes the device code
  (`_record_user_code_failure`), and an audit write that fails after an approval
  withdraws the pairing outright (`_withdraw_pairing`), both on the reasoning
  that "the recovery the customer needs is a fresh QR anyway".
```

with

```markdown
- **This repository already chose this trade twice.** A single mistyped pairing
  code at the attempt-budget floor revoked the device code
  (`_record_user_code_failure`, removed on 30 September 2026 with the attempt
  budget, when the pairing code became the lookup key), and an audit write that
  fails after an approval withdraws the pairing outright (`_withdraw_pairing`),
  both on the reasoning that "the recovery the customer needs is a fresh QR
  anyway".
```

The rest of the record is a dated decision and stays as written.

- [ ] **Step 6: Prove the named documents no longer describe removed things as current**

Run: `grep -n "USER_CODE_MAX_ATTEMPTS\|user_code_attempts\|approve_device_code\|update_device_code" docs/user-guide/getting-started.md docs/user-guide/components/confirm-service.md docs/user-guide/components/session-store.md`
Expected: no output.

Run: `grep -n "_record_user_code_failure" dev-docs/decisions/0012-device-code-single-use.md`
Expected: exactly one line, the one carrying "removed on 30 September 2026".

- [ ] **Step 7: Run the gate**

Run: `make ci`
Expected: exit 0. Measured on a copy of the tree after all twelve tasks: 3126 passed in 198 seconds.

- [ ] **Step 8: Commit**

```bash
git add dev-docs/decisions/0021-public-html-on-the-write-key-service.md docs/user-guide/getting-started.md docs/user-guide/components/confirm-service.md docs/user-guide/components/session-store.md dev-docs/decisions/0012-device-code-single-use.md
git commit -m "docs: record public HTML on the write-key service and retire the attempt budget" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 13: `CLAUDE.md` and `docs/user-guide/getting-started.md`

Added after the plan was approved, at the user's request. It changes only the `CLAUDE.md` statements that Tasks 1 to 12 make false, and adds the eight new variables to the confirm table in `docs/user-guide/getting-started.md`. Every fact below was checked against a copy of the tree with Tasks 1 to 12 applied, on 30 September 2026:
- `grep -rln "HTMLResponse\|text/html" services stub packages` finds only `services/confirm/verify_page.py`.
- The four paths that check ZT-7 revocation are `/scan`, `/approve`, `/token` and the challenge callback.
- `make ci` exited 0 on 3126 tests, none failed and none skipped, in 198.19 and 201.97 seconds.

There is no test to write for documentation. The checks are Step 3's `make citations` and Step 4's `make ci`.

**Files:**
- Modify: `CLAUDE.md` (five sentence fragments in "Repository state"; nothing else)
- Modify: `docs/user-guide/getting-started.md` (eight new rows in the "Confirm Service" table)

- [ ] **Step 1: `CLAUDE.md`, only the statements this work makes false**

Each edit is a fragment inside one long paragraph line. Replace exactly the old fragment with the new one and leave the rest of the line as it is.

1a. Test count, first paragraph of "Repository state". Old:

```
`make ci` exits 0 on 2877 tests, none failed and none skipped, in 182 to 189 seconds with Docker up (three runs, measured 27 September 2026).
```

New:

```
`make ci` exits 0 on 3126 tests, none failed and none skipped, in 198 to 202 seconds with Docker up (two runs, measured 30 September 2026 after the QR page and scan work).
```

1b. Same paragraph. Old: `is inside that 2877 like every other file.` New: `is inside that 3126 like every other file.`

Before 1a and 1b, run `make ci` on your own tree after Task 12. If the count is not 3126, stop: a task diverged from this plan, and that has to be found before the count is written down.

1c. The `services/confirm` paragraph, the device grant's endpoints. Old:

```
it holds the RFC 8628 device grant (`POST /device_authorization`, `POST /token`, `POST /approve`) and the challenge approval callback
```

New:

```
it holds the RFC 8628 device grant (`POST /device_authorization`, `POST /token`, `POST /scan`, `POST /approve`, and the browser's pairing page at `GET /verify` with `/verify/qr.svg`, `/verify/state`, `/verify.js` and `/verify.css`) and the challenge approval callback
```

1d. Same paragraph, `PUBLIC_PATHS` and `/approve`. Old:

```
only `/.well-known/jwks.json`, `/device_authorization` and `/token` are in `PUBLIC_PATHS`, so `/approve` and the challenge callback both require a verified banking-app assertion;
```

New:

```
only `/.well-known/jwks.json`, `/device_authorization`, `/token` and the five `/verify` routes are in `PUBLIC_PATHS` (decision record 0021 is why the page is served here), so `/scan`, `/approve` and the challenge callback all require a verified banking-app assertion; `/approve` takes the pairing's `user_code` and nothing else that names it, and approves only for the customer whose app scanned it first at `/scan`, by compare-and-set in the device-code store;
```

1e. Same paragraph, the revocation count. Old: `a ZT-7 revocation check refuses a revoked customer on all three paths that know one;` New: `a ZT-7 revocation check refuses a revoked customer on all four paths that know one;`

1f. The "What does not" paragraph. Old:

```
Also absent: the QR page (`POST /device_authorization` returns a `verification_uri_complete` for a browser to encode; no HTML is served anywhere in this repo), and a payments producer.
```

New:

```
Also absent: a payments producer. The QR page is not absent any more: since 30 September 2026 `verification_uri_complete` opens `GET /verify` on `services/confirm`, which is the only HTML this repository serves.
```

Nothing else in `CLAUDE.md` changes. The Architecture table still puts the QR page on `services/api`, and it stays that way: the paragraph above it says to read that table as the target, and the `services/confirm` paragraph already records where the device grant actually lives.

Run: `git diff --stat CLAUDE.md`
Expected: `1 file changed, 3 insertions(+), 3 deletions(-)`. The six fragments sit on three lines: the "Repository state" paragraph, the `services/confirm` paragraph and the "What does not" paragraph.

- [ ] **Step 2: `docs/user-guide/getting-started.md`, the new variables**

All edits are in the "Confirm Service (`services/confirm/settings.py`)" table.

2a. Directly after the row `| `POSTERN_CONFIRM_RATE_LIMIT_CHALLENGE_APPROVE` | No | `60` | As above, for the challenge approval callback |` and before the `POSTERN_CONFIRM_RATE_LIMIT_DEFAULT` row, insert:

```markdown
| `POSTERN_CONFIRM_RATE_LIMIT_SCAN` | No | `60` | As above, for `/scan`. Raise it for the same reason as `/approve`'s |
| `POSTERN_CONFIRM_RATE_LIMIT_VERIFY` | No | `60` | As above, for the pairing page `/verify`: page loads plus the 12 a minute its noscript refresh adds |
| `POSTERN_CONFIRM_RATE_LIMIT_VERIFY_QR` | No | `300` | As above, for `/verify/qr.svg`, which the page reloads every two seconds: 30 a minute per open tab, so 300 is ten tabs behind one address |
| `POSTERN_CONFIRM_RATE_LIMIT_VERIFY_STATE` | No | `300` | As above, for `/verify/state`, which the page polls every two seconds |
| `POSTERN_CONFIRM_RATE_LIMIT_VERIFY_JS` | No | `60` | As above, for `/verify.js`, loaded once per page |
| `POSTERN_CONFIRM_RATE_LIMIT_VERIFY_CSS` | No | `60` | As above, for `/verify.css`, loaded once per page |
```

2b. Directly after the `POSTERN_CONFIRM_CUSTOMER_RATE_LIMIT_CHALLENGE_APPROVE` row, insert:

```markdown
| `POSTERN_CONFIRM_CUSTOMER_RATE_LIMIT_SCAN` | No | `10` | As above, for `/scan`, which precedes every pairing approval once. **At least 1** |
```

2c. Directly after the `POSTERN_DEVICE_VERIFICATION_URI` row, insert the one variable a deployment must set:

```markdown
| `POSTERN_DEVICE_APP_LINK_URI` | **Yes, in any deployment** | `https://app.postern.internal/pair` | Base of the universal link / app link the pairing QR encodes, as `?user_code=...&qr=...`. The default is a local placeholder: a deployment must set its own host and publish the Apple associated-domains and Android asset-links files for it, or a phone camera will not open the bank app. **Refused at startup** when its host equals `POSTERN_DEVICE_VERIFICATION_URI`'s host (case-insensitive, port ignored) |
```

Its Required column reads **Yes, in any deployment** and not a bare **Yes**, because the service starts without it: the default is a `.internal` placeholder that serves local work and opens no real app.

Run: `grep -c "POSTERN_CONFIRM_RATE_LIMIT_VERIFY\|POSTERN_CONFIRM_RATE_LIMIT_SCAN\|POSTERN_CONFIRM_CUSTOMER_RATE_LIMIT_SCAN\|POSTERN_DEVICE_APP_LINK_URI" docs/user-guide/getting-started.md`
Expected: `8`.

- [ ] **Step 3: Citations**

Run: `make citations`
Expected: exit 0 and no problem lines. Measured on the copy of the tree with Tasks 1 to 13 applied and this plan file present, the line was `citations: 448 anchored resolved (224 node-id, 224 possessive; 40 into site-packages), 89 bare grandfathered (baseline 91)`. The resolved count moves if any tracked file has gained or lost citations since.

- [ ] **Step 4: The gate**

Run: `make ci`
Expected: exit 0, `3126 passed`.

- [ ] **Step 5: Commit**

```bash
git add CLAUDE.md docs/user-guide/getting-started.md
git commit -m "docs: bring CLAUDE.md and getting-started up to date with the QR pairing" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

## Spec coverage

Every section of `dev-docs/qr-page-spec.md` and every item of its Testing section, and the task that implements or tests it.

| Spec item | Task |
|---|---|
| §1 `DeviceCode` gains `display_handle`, `qr_secret`, `creator_ip`, `scanned_by`, `scanned_at` | 2 |
| §1 `exchanged_at` kept, row survives consume on both backends | 3 (lookups still resolve after consume), 4 (`conflict_exchanged`) |
| §1 old record deserializes with no `qr_secret`, unscannable | 2 |
| §1 `user_code_attempts` removed | 8 |
| §1 `get_by_display_handle` / `get_by_user_code`, `SET NX EX`, collision retries, deleted on revoke only, left by consume, lookup re-reads and re-checks; in-memory dicts cleared by `_drop_expired` and `revoke_device_code` | 3 |
| §1 `claim_scan` and its six `ScanClaim` results | 4 |
| §1 `approve_scanned` compare-and-set | 4 |
| §1 `update_device_code` and `approve_device_code` removed from the base class and both backends | 8 |
| §2 slot, MAC construction, fixed-width input, window `now-5..now+1`, future slot invalid not stale, code constants | 1 |
| §3 `verification_uri_complete` is `?d=<display_handle>`; `verification_uri` and `user_code` unchanged | 7 |
| §3 app link `{device_app_link_uri}?user_code=..&qr=<slot>.<mac>` | 10 (`app_link`) |
| §3 `POSTERN_DEVICE_APP_LINK_URI`: field, `from_env` default, `env_inventory` row | 5 |
| §3 startup refusal on a shared host, `urlsplit`, case-folded, `ValueError` | 5 |
| §3 bare `GET /verify` shows one sentence, no form | 10 |
| §3 decision record 0021 | 12 |
| §4 five routes in `PUBLIC_PATHS` with a reason each, eight in all | 10 |
| §4 plain `Route`s, not a `Mount` | 10 (`verify_page_routes`, `test_every_public_path_is_a_route_with_methods`) |
| §4 page-state table, three closed cases indistinguishable, `/verify` 200 in all states, `qr.svg` 404 for scanned and closed, `/verify/state` 404 for closed | 10 |
| §4 page renders stored `display_handle` and `user_code` only | 10 |
| §4 page headers: CSP, `Referrer-Policy`, `Cache-Control`, `nosniff`, HSTS, `X-Frame-Options`, noscript refresh 5 s in pending and scanned only | 10 |
| §4 `/verify/state` bodies and headers, same `Sec-Fetch-Site` refusal | 10 |
| §4 `qr.svg` by `segno`, headers incl. its own CSP and CORP | 10 |
| §4 hotlink refusal: anything but exactly `same-origin`, including a missing header; CORP on every answer | 10 |
| §4 `verify.js` behaviour: pending, scanned, 404, 429 back-off 2 s to 30 s | 10 (`services/confirm/static/verify.js`) |
| §4 `verify.css` served as `text/css` with `nosniff` | 10 |
| §4 `segno` 1.6.6 in the root `pyproject.toml` | 10 |
| §5 `/scan` assertion-authenticated, not public | 9 |
| §5 steps 1 to 6, every `claim_scan` mapping, `client_id_verified: false` | 9 |
| §5 identical `invalid_grant` for unknown, expired, approved, bad MAC, future slot; distinct `qr_stale` and `scan_conflict` | 9 |
| §5 stale token from another customer answers `qr_stale`, revokes nothing | 9 |
| §6 body `{user_code}`, `device_code` refused 400 `invalid_request` with no row | 8 |
| §6 lookup then `approve_scanned`; label order `user_code_not_found`, `not_scanned`, `scanned_by_other`, `already_approved`; identical `invalid_grant`; 401 and 403 unchanged | 8 |
| §7 `/scan` one row per recorded call, fail-closed withdrawal, `SCAN_TOOL_NAME`, `SCAN_ROUTE` | 9 |
| §7 success is `returned` with NULL `detail` on both routes | 8, 9 |
| §7 `DETAIL_USER_CODE_NOT_FOUND`, `DETAIL_QR_INVALID`, `DETAIL_QR_STALE`, `DETAIL_SCAN_CONFLICT` | 8, 9 |
| §7 `DETAIL_NOT_SCANNED`, `DETAIL_SCANNED_BY_OTHER` | 8 |
| §7 `DETAIL_ALREADY_APPROVED` docstring rewritten | 8, 9 |
| §7 `DETAIL_USER_CODE_MISMATCH`, `DETAIL_USER_CODE_BUDGET_EXHAUSTED` kept as historical | 8 |
| §7 no migration | nothing to do: `detail` is unconstrained `Text` |
| §8 six per-address limits and `/scan`'s per-customer 10, each a setting with an `env_inventory` row | 6 |
| §8 `BodySizeLimit` unchanged, path-list tests updated | 10 |
| §9 `user_code_max_attempts` and `POSTERN_USER_CODE_MAX_ATTEMPTS` removed with their row | 8 |
| Testing: rotation token (slot boundaries, both window edges, future slot, tampered MAC, other `user_code`, fixed width) | 1 |
| Testing: store on both backends (lookups, cleanup on revoke, secondaries after consume, `SET NX` retry, every `claim_scan` result, `approve_scanned` refusals, two concurrent approvals, no `update_device_code`/`approve_device_code`) | 2, 3, 4, 8 |
| Testing: `/scan` (every refusal, identical body, distinct bodies, both session-swap cases, success fields, rows, fail-closed withdrawal) | 9 |
| Testing: `/approve` (new body, `scanned_by_other`, `not_scanned`, revoked or expired between, identical body, legacy body 400 with no row) | 8 |
| Testing: page, image and state (every header, stored values, state table rows, state bodies, `app_link` across slots, 404s, hotlink refusal on four header shapes, CORP on every answer, CSS type) | 10 |
| Testing: settings (default, inventory row, shared-host refusal incl. case-only) | 5 |
| Testing: wiring (exactly eight public paths, route-table test, limits in both tables) | 6, 10 |
| Testing: end to end over ASGI | 11 |
| Testing: existing tests that pin old behaviour, and the ~65 `/approve` bodies | 5, 6, 7, 8, 10 |
| Docs that go stale | 12 |
| Added at approval: `CLAUDE.md` statements this work makes false, and the new variables in `docs/user-guide/getting-started.md` | 13 |

## Spec discrepancies found while planning

Each is a point where the spec and the code at `5eb0500` disagree, or where the spec leaves a case open. None is resolved by changing the design; the plan takes the most conservative reading and says so here.

1. **`DETAIL_DEVICE_CODE_NOT_FOUND` is not "live at `/token`".** Spec §7 keeps the literal because it "stays live at `/token`, where a lookup by `device_code` misses". It does not: `services/confirm/device_auth.py::token_endpoint` answers an unknown device code before any identity is read and writes no row, by `PairingAudit`'s rule, and `tests/test_pairing_audit.py`'s `test_an_unknown_device_code_at_the_token_endpoint_writes_nothing` pins exactly that. Its only writer was `/approve`'s `device_code` lookup, which Task 8 removes. **Plan:** keep the constant (rows carrying it exist and `audit_log` is append-only), keep it out of `/token`, and document it as historical beside `DETAIL_USER_CODE_MISMATCH` and `DETAIL_USER_CODE_BUDGET_EXHAUSTED` (Task 8, Step 10b). The spec's actual reason for a new literal -- a 30-bit guess must not be filed with a 256-bit one -- holds either way.

2. **The spec's own citation breaks the gate it will be merged under.** §1's paragraph on the removed methods cites `_record_user_code_failure` in the anchored node-id form. `tools/check_citations.py` resolves anchored citations in every tracked file, so once Task 8 deletes the function `make citations` fails on `dev-docs/qr-page-spec.md`. Measured on a copy of the tree with Task 8 applied: exactly that one problem. **Plan:** Task 8, Step 13 rewrites that one citation to name the function without the anchor. The sentence's meaning is unchanged. (This plan file avoids the anchored form for every symbol that does not exist both now and after the last task, for the same reason.)

3. **`claim_scan`'s six results do not cover an unscanned, approved row.** §1's table has no entry for `scanned_by == ""` with `approved` true. Nothing this change writes produces one; a record approved by the previous release does. **Plan:** `GONE` (Task 4, `_scan_verdict`, with a test). Such a record also carries no `qr_secret`, so `POST /scan` refuses it at step 4 with `qr_invalid` before `claim_scan` is reached.

4. **What a lost compare-and-set race answers is not specified.** `consume_device_code` answers `False` after three beaten `WATCH`es. For `claim_scan` and `approve_scanned` a `False`/`GONE` would force `/approve`'s re-read into a fifth shape the §6 label order does not name (scanned by this customer, unexpired, unapproved). **Plan:** both raise `DeviceCodeStoreContended` on exhaustion, which the handlers record under the exception's type name, as every other unexpected exception on these paths is (Task 3 defines it, Task 4 raises it). `_approve_refusal_detail` raises `RuntimeError` if it ever reads that fifth shape, which neither backend can produce.

5. **"One `audit_log` row per call" at `/scan` versus `PairingAudit`'s rule.** §7 says `/scan` writes one row per call; the Testing section asks for "one audit row per branch with the `detail` in §7's table", which has no malformed-body entry, and `PairingAudit`'s documented rule writes nothing for a request refused on its shape alone, as `/approve` already does. **Plan:** malformed bodies and the 401 write no row (Task 9, `test_a_malformed_body_is_invalid_request_with_no_row`).

6. **`/scan` with an unreachable revocation store is not specified.** **Plan:** the shape `/approve` already has: `RevocationStoreUnavailable` propagates, is recorded under its type name, and the app gets a 500 (Task 9).

7. **The `/scan` success body's field names.** §5 step 6 lists `client_id`, `client_id_verified`, `scopes`, `expires_at` and "the pairing code". **Plan:** the pairing code as `user_code` in its display form, `expires_at` as ISO 8601 (Task 9, `_scan_context_response`).

8. **`/verify.js`'s headers are not listed.** §4 lists `Content-Type` and `nosniff` for the stylesheet only. **Plan:** the script gets the same two, as `text/javascript` (Task 10).

## Concerns for the reviewer

- **`CLAUDE.md` is stale between Task 8 and Task 13.** Task 13 fixes it at the end, and each intermediate commit is still green, because nothing checks that file's prose.
- **`POSTERN_DEVICE_VERIFICATION_URI`'s row in `docs/user-guide/getting-started.md` still says "(QR code target)".** After Task 10 the QR encodes the app link, not the page URI. Task 13 was scoped to adding rows, so it leaves that phrase alone.
- **Two docstrings run ahead of their code by one or two commits**: `_unpairable_response` (Task 8) mentions `POST /scan` (Task 9), and `verify_page.py` and the `PUBLIC_PATHS` comment (Task 10) name decision record 0021 (Task 12). Neither is an anchored citation, so no gate fails in between.
- **Task 11 has no red step.** It exercises code Tasks 1 to 10 built, so it passes on first run by construction.
- **The flow completes only in tests** until the mobile team builds the app's `/scan` call and confirmation screen and the operator publishes the universal-link and app-link files for `POSTERN_DEVICE_APP_LINK_URI`'s host. Both are in the spec's "Owed outside this repository".

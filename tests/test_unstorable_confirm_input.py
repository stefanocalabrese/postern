"""`services/confirm` refuses what the audit row and the session token cannot carry.

U+0000 and a lone surrogate are the two things a caller can send as a JSON
escape (`"\\u0000"`, `"\\ud800"`) that a string field of the pairing cannot
carry onward: PostgreSQL text refuses NUL, and UTF-8 cannot encode a surrogate.
Until 2026-10-07 `POST /device_authorization` checked `client_id` for type and
length only, so `{"client_id": "\\ud800"}` was a 200 with a device code, and
after a customer scanned and approved it `POST /token` answered 500 (a
`UnicodeEncodeError` writing the audit row). `"a\\u0000b"` was minted into the
session token's `client_id`.

The rule lives once, in `postern_core.unstorable`, and `services/api`'s body
walk uses the same function. This file drives it through the real confirm app:

* `POST /device_authorization` refuses it in `client_id` and in `scopes`;
* every other route that takes a caller-supplied string is probed with the same
  characters and must answer the refusal it already has, never a 500;
* ordinary non-ASCII text is still accepted, edges included (U+D7FF and U+E000
  sit either side of the surrogate block), and a pairing carrying it completes.
"""

from __future__ import annotations

import json
import re
from collections.abc import AsyncIterator
from dataclasses import replace
from pathlib import Path
from typing import Any
from uuid import uuid4

import httpx2
import pytest
from fastmcp.server.auth.providers.jwt import JWTVerifier, RSAKeyPair
from postern_core.auth.device_codes import RedisDeviceCodeStore
from postern_core.auth.device_keys import no_enrolled_devices
from postern_core.store.engine import Database
from postern_core.store.models import AuditEntry
from postern_core.unstorable import contains_unstorable_character
from sqlalchemy import func, select
from starlette.applications import Starlette

from services.confirm.main import create_confirm_app
from services.confirm.settings import ConfirmSettings
from tests.device_grant_helpers import (
    device_store_of,
    qr_for,
    scan_in_store,
    session_claims,
    stored_code,
)
from tests.fixtures.append_only_bypass import (
    delete_audit_rows_by_bypassing_the_append_only_triggers,
)

ISSUER = "https://app.test.invalid"
AUDIENCE = "postern-confirm"
ALICE = "cust_a11ce"
JSON_HEADERS = {"content-type": "application/json"}
REPO = Path(__file__).resolve().parent.parent

NUL = "\x00"
#: JSON text for each unstorable shape, written as ESCAPES because a lone
#: surrogate cannot be a Python `str` that encodes to UTF-8.
BAD_JSON_STRINGS = {
    "high_surrogate": r"\ud800",
    "low_surrogate": r"\udfff",
    "reversed_pair": r"\udc00\ud800",
    "nul": r"\u0000",
    "nul_inside": r"a\u0000b",
    "surrogate_inside": r"a\ud800b",
    "lone_high_before_text": r"\ud83dx",
}
#: Text that is unusual and storable.
GOOD_TEXT = {
    "latin": "café",
    "cjk": "客户端",
    "emoji": "\U0001f600",
    "first_supplementary": "\U00010000",
    "just_below_surrogates": chr(0xD7FF),
    "just_above_surrogates": chr(0xE000),
    "escaped_valid_pair": None,  # sent as r"😀", decodes to U+1F600
}


# ---------------------------------------------------------------------------
# The shared rule.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("", False),
        ("plain", False),
        ("café", False),
        ("\U0001f600", False),
        ("\U00010000", False),
        (chr(0xD7FF), False),
        (chr(0xE000), False),
        (chr(0xFFFF), False),
        (chr(0x10FFFF), False),
        (chr(0x01), False),
        (chr(0x7F), False),
        (NUL, True),
        ("a" + NUL + "b", True),
        (chr(0xD800), True),
        (chr(0xDBFF), True),
        (chr(0xDC00), True),
        (chr(0xDFFF), True),
        (chr(0xDC00) + chr(0xD800), True),
        ("ok" + chr(0xD800) + "ok", True),
    ],
)
def test_the_rule_refuses_nul_and_the_surrogate_block_and_nothing_next_to_them(
    value: str, expected: bool
) -> None:
    assert contains_unstorable_character(value) is expected


def test_no_second_copy_of_the_rule_survives_outside_its_module() -> None:
    """The regexp and the range live in `postern_core/unstorable.py` only.

    A copy is a rule that drifts: a call site widened or narrowed alone. The
    pattern is the surrogate range as it would be written in a character class.
    """
    # A range written as a character class (`\ud800-\udfff`) or as hex bounds.
    # Prose that merely names a surrogate in a docstring does not match.
    needle = re.compile(r"ud800\s*-\s*\\?udfff|0xd800|0xdfff", re.IGNORECASE)
    owner = REPO / "packages" / "postern-core" / "src" / "postern_core" / "unstorable.py"
    offenders = [
        str(path.relative_to(REPO))
        for root in ("packages", "services")
        for path in (REPO / root).rglob("*.py")
        if path != owner and needle.search(path.read_text())
    ]
    assert offenders == []


def test_the_call_sites_import_the_shared_rule() -> None:
    for relative in (
        "services/api/asgi/header_validation.py",
        "services/confirm/device_auth.py",
    ):
        source = (REPO / relative).read_text()
        assert "contains_unstorable_character" in source, relative


# ---------------------------------------------------------------------------
# Fixtures.
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def key_pair() -> RSAKeyPair:
    return RSAKeyPair.generate()


@pytest.fixture()
def app(pg_url: str, key_pair: RSAKeyPair) -> Starlette:
    verifier = JWTVerifier(public_key=key_pair.public_key, issuer=ISSUER, audience=AUDIENCE)
    return create_confirm_app(
        replace(ConfirmSettings.for_testing(), database_url=pg_url),
        assertion_verifier=verifier,
        device_key_store=no_enrolled_devices(),
    )


@pytest.fixture()
async def clean(database: Database) -> AsyncIterator[Database]:
    await _wipe(database)
    yield database
    await _wipe(database)


async def _wipe(db: Database) -> None:
    async with db.sessionmaker() as s:
        await delete_audit_rows_by_bypassing_the_append_only_triggers(s)
        await s.commit()


async def audit_count(db: Database) -> int:
    async with db.sessionmaker() as s:
        return int((await s.execute(select(func.count()).select_from(AuditEntry))).scalar_one())


def bearer(key_pair: RSAKeyPair, subject: str = ALICE) -> dict[str, str]:
    token = key_pair.create_token(
        subject=subject, issuer=ISSUER, audience=AUDIENCE, expires_in_seconds=60
    )
    return {"Authorization": f"Bearer {token}"}


def client(app: Starlette) -> httpx2.AsyncClient:
    """`raise_app_exceptions=False`: a handler bug is the 500 it would be on the wire."""
    return httpx2.AsyncClient(
        transport=httpx2.ASGITransport(app=app, raise_app_exceptions=False),
        base_url="http://t",
    )


async def post_json(
    app: Starlette, path: str, raw: str | bytes, headers: dict[str, str] | None = None
) -> httpx2.Response:
    content = raw.encode() if isinstance(raw, str) else raw
    async with client(app) as c:
        return await c.post(path, content=content, headers={**JSON_HEADERS, **(headers or {})})


async def post_form(
    app: Starlette, path: str, raw: str | bytes, headers: dict[str, str] | None = None
) -> httpx2.Response:
    content = raw.encode() if isinstance(raw, str) else raw
    h = {"content-type": "application/x-www-form-urlencoded", **(headers or {})}
    async with client(app) as c:
        return await c.post(path, content=content, headers=h)


def codes_held(app: Starlette) -> int:
    return len(device_store_of(app)._codes)  # type: ignore[attr-defined]


def refusal(resp: httpx2.Response) -> dict[str, Any]:
    assert resp.status_code == 400, resp.text
    body: dict[str, Any] = resp.json()
    assert body["error"] == "invalid_request"
    return body


# ---------------------------------------------------------------------------
# POST /device_authorization: client_id and scopes.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("escape", list(BAD_JSON_STRINGS.values()), ids=list(BAD_JSON_STRINGS))
async def test_client_id_with_an_unstorable_character_is_refused(
    app: Starlette, clean: Database, escape: str
) -> None:
    before_codes, before_rows = codes_held(app), await audit_count(clean)

    resp = await post_json(app, "/device_authorization", '{"client_id": "' + escape + '"}')

    body = refusal(resp)
    assert body["error_description"] == "client_id contains a character that cannot be stored"
    assert resp.text.count("ud800") == 0 and "\\u0000" not in resp.text  # nothing echoed
    assert codes_held(app) == before_codes
    assert await audit_count(clean) == before_rows


@pytest.mark.parametrize("escape", list(BAD_JSON_STRINGS.values()), ids=list(BAD_JSON_STRINGS))
async def test_scopes_with_an_unstorable_character_are_refused(
    app: Starlette, clean: Database, escape: str
) -> None:
    """Every entry of the space-separated `scopes` string is covered: the check
    is on the whole string, so it cannot miss the second or the last entry."""
    before_codes, before_rows = codes_held(app), await audit_count(clean)

    for scopes in (escape, "accounts:read " + escape, escape + " accounts:read"):
        resp = await post_json(
            app, "/device_authorization", '{"client_id": "ok", "scopes": "' + scopes + '"}'
        )
        body = refusal(resp)
        assert body["error_description"] == "scopes contains a character that cannot be stored"

    assert codes_held(app) == before_codes
    assert await audit_count(clean) == before_rows


async def test_a_nul_in_a_form_encoded_client_id_or_scopes_is_refused(
    app: Starlette, clean: Database
) -> None:
    for raw in ("client_id=a%00b", "client_id=ok&scopes=a%00b"):
        resp = await post_form(app, "/device_authorization", raw)
        refusal(resp)
    assert codes_held(app) == 0


async def test_a_surrogate_in_form_encoded_bytes_never_becomes_a_stored_string(
    app: Starlette, clean: Database
) -> None:
    """CESU-8 bytes for U+D800 (`ED A0 80`) in a urlencoded body: whatever the
    form parser makes of them, the answer is a 200 whose pairing holds only
    storable text, or a 400. Never a 500."""
    resp = await post_form(app, "/device_authorization", b"client_id=%ED%A0%80")
    assert resp.status_code in (200, 400), resp.text
    for code in device_store_of(app)._codes.values():  # type: ignore[attr-defined]
        assert not contains_unstorable_character(code.client_id)
        assert not contains_unstorable_character(code.scopes)


@pytest.mark.parametrize("name", list(GOOD_TEXT))
async def test_ordinary_unicode_client_id_and_scopes_pair_approve_and_mint(
    app: Starlette, clean: Database, key_pair: RSAKeyPair, name: str
) -> None:
    """The full pair -> scan -> approve -> /token flow with a client_id and a
    scopes string carrying the text, edges of the surrogate block included."""
    if GOOD_TEXT[name] is None:
        value, wire = "\U0001f600", r"😀"
    else:
        value = GOOD_TEXT[name] or ""
        wire = json.dumps(value, ensure_ascii=False)[1:-1]
    body = '{"client_id": "' + wire + '", "scopes": "accounts:read ' + wire + '"}'

    resp = await post_json(app, "/device_authorization", body)
    assert resp.status_code == 200, resp.text
    device = resp.json()
    stored = await stored_code(app, device["user_code"])
    assert stored.client_id == value
    assert stored.scopes == "accounts:read " + value

    await scan_in_store(app, device["user_code"], ALICE)
    approved = await post_json(
        app, "/approve", json.dumps({"user_code": device["user_code"]}), bearer(key_pair)
    )
    assert approved.status_code == 200, approved.text

    token = await post_form(
        app, "/token", f"grant_type=device_code&device_code={device['device_code']}"
    )
    claims = session_claims(token, app)
    assert claims["sub"] == ALICE
    assert claims["client_id"] == value


# ---------------------------------------------------------------------------
# The other routes that take a caller-supplied string.
# ---------------------------------------------------------------------------


@pytest.fixture(params=["memory", "redis"])
async def probed(request: pytest.FixtureRequest, app: Starlette) -> AsyncIterator[Starlette]:
    """The app over the in-memory device-code store and over a real Redis one.

    A Redis key is encoded to UTF-8 on the way out, which is where a lone
    surrogate in a `user_code` would raise; the in-memory store never encodes.
    """
    if request.param == "redis":
        url: str = request.getfixturevalue("redis_url")
        store = RedisDeviceCodeStore(
            url=url, default_ttl=900, key_prefix=f"t{uuid4().hex[:12]}:", max_codes=10_000
        )
        app.state.device_code_store = store
        yield app
        await store.close()
        return
    yield app


async def _new_pairing(app: Starlette) -> dict[str, Any]:
    resp = await post_json(app, "/device_authorization", '{"client_id": "browser"}')
    assert resp.status_code == 200, resp.text
    body: dict[str, Any] = resp.json()
    return body


#: Six-character values (the stored code length) so they get past the length
#: gate and reach the store lookup, plus the short forms.
BAD_USER_CODES = [
    r"\ud800" * 6,
    r"AB\ud800CDE",
    r"\udfff" * 6,
    r"AB\u0000CDE",
    r"\u0000" * 6,
    r"\ud800",
    r"\u0000",
]


@pytest.mark.parametrize("escape", BAD_USER_CODES)
async def test_scan_with_an_unstorable_user_code_is_the_answer_for_an_unknown_one(
    probed: Starlette, clean: Database, key_pair: RSAKeyPair, escape: str
) -> None:
    unknown = await post_json(
        probed, "/scan", '{"user_code": "ZZZZZZ", "qr": "x"}', bearer(key_pair)
    )
    assert unknown.status_code == 400
    resp = await post_json(
        probed, "/scan", '{"user_code": "' + escape + '", "qr": "x"}', bearer(key_pair)
    )
    assert (resp.status_code, resp.json()) == (unknown.status_code, unknown.json()), resp.text


@pytest.mark.parametrize("escape", BAD_USER_CODES)
async def test_approve_with_an_unstorable_user_code_is_the_answer_for_an_unknown_one(
    probed: Starlette, clean: Database, key_pair: RSAKeyPair, escape: str
) -> None:
    unknown = await post_json(probed, "/approve", '{"user_code": "ZZZZZZ"}', bearer(key_pair))
    assert unknown.status_code == 400
    resp = await post_json(probed, "/approve", '{"user_code": "' + escape + '"}', bearer(key_pair))
    assert (resp.status_code, resp.json()) == (unknown.status_code, unknown.json()), resp.text


@pytest.mark.parametrize("escape", [r"\ud800", r"\udfff", r"\u0000", r"a\u0000b", r"\udc00\ud800"])
async def test_scan_with_an_unstorable_qr_token_is_refused_like_a_forged_one(
    probed: Starlette, clean: Database, key_pair: RSAKeyPair, escape: str
) -> None:
    device = await _new_pairing(probed)
    forged = await post_json(
        probed,
        "/scan",
        json.dumps({"user_code": device["user_code"], "qr": "forged"}),
        bearer(key_pair),
    )
    assert forged.status_code == 400
    resp = await post_json(
        probed,
        "/scan",
        '{"user_code": "' + device["user_code"] + '", "qr": "' + escape + '"}',
        bearer(key_pair),
    )
    assert (resp.status_code, resp.json()) == (forged.status_code, forged.json()), resp.text


async def test_a_valid_scan_still_works_after_those_probes(
    probed: Starlette, clean: Database, key_pair: RSAKeyPair
) -> None:
    device = await _new_pairing(probed)
    code = await stored_code(probed, device["user_code"])
    resp = await post_json(
        probed,
        "/scan",
        json.dumps({"user_code": device["user_code"], "qr": qr_for(code)}),
        bearer(key_pair),
    )
    assert resp.status_code == 200, resp.text


@pytest.mark.parametrize(
    "raw",
    [
        "grant_type=device_code&device_code=a%00b",
        "grant_type=device_code&device_code=%00",
        "grant_type=a%00b",
        "grant_type=device_code&device_code=x&resource=a%00b",
        "grant_type=refresh_token&refresh_token=a%00b",
        "grant_type=refresh_token&refresh_token=prt1.%00.%00",
        "grant_type=refresh_token&refresh_token=prt1.a%00b.c",
        "device_code=%ED%A0%80&grant_type=device_code",
        "grant_type=device_code&device_code=%ED%A0%80%ED%B0%80",
        "grant_type=refresh_token&refresh_token=%ED%A0%80",
        "grant_type=%ED%A0%80",
        "grant_type=refresh_token&refresh_token=prt1.%ED%A0%80.x",
    ],
)
async def test_token_form_fields_with_unstorable_characters_never_500(
    probed: Starlette, clean: Database, raw: str
) -> None:
    before = await audit_count(clean)
    resp = await post_form(probed, "/token", raw)
    assert resp.status_code in (400, 404), (resp.status_code, resp.text)
    assert resp.json()["error"] in {
        "invalid_request",
        "invalid_grant",
        "invalid_target",
        "unsupported_grant_type",
    }
    assert await audit_count(clean) == before


async def test_token_multipart_fields_with_nul_never_500(
    probed: Starlette, clean: Database
) -> None:
    async with client(probed) as c:
        resp = await c.post(
            "/token",
            files={
                "grant_type": (None, b"device_code"),
                "device_code": (None, b"a\x00b"),
            },
        )
    assert resp.status_code == 400, resp.text
    assert resp.json()["error"] in {"invalid_request", "invalid_grant"}


# ---------------------------------------------------------------------------
# `clip_tree` is recursive and unbounded: it is safe only behind `scrub_tree`.
# ---------------------------------------------------------------------------


def test_clip_tree_alone_raises_on_a_9000_deep_tree() -> None:
    """The reason the call-site list below exists: on its own input it fails."""
    from postern_core.store.audit import clip_tree

    tree: Any = "leaf"
    for _ in range(9_000):
        tree = {"d": tree}
    with pytest.raises(RecursionError):
        clip_tree(tree)


def test_the_public_audit_entry_point_survives_a_9000_deep_arguments_tree() -> None:
    """Through `_arguments` (scrub, then clip, then cap), which is how the api
    reaches `clip_tree`: the scrub cuts depth at 100 first."""
    from postern_core.domain.masking import TOO_DEEP, redaction_budget

    from services.api.middleware.audit import _arguments

    tree: Any = "leaf"
    for _ in range(9_000):
        tree = {"d": tree}
    with redaction_budget():
        out = _arguments({"deep": tree})
    assert TOO_DEEP in repr(out)


def _callers_of_the_clipper() -> set[tuple[str, str]]:
    """`(file, enclosing function)` for every call of `clip_tree` or
    `bound_arguments` (which calls it) in `packages/` and `services/`."""
    import ast

    names = {"clip_tree", "_clip_tree", "bound_arguments"}
    found: set[tuple[str, str]] = set()
    for root in ("packages", "services"):
        for path in sorted((REPO / root).rglob("*.py")):
            tree = ast.parse(path.read_text())
            for fn in ast.walk(tree):
                if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                for node in ast.walk(fn):
                    if not isinstance(node, ast.Call):
                        continue
                    target = node.func
                    called = (
                        target.id
                        if isinstance(target, ast.Name)
                        else target.attr
                        if isinstance(target, ast.Attribute)
                        else None
                    )
                    if called in names:
                        found.add((str(path.relative_to(REPO)), fn.name))
    return found


#: Each of these hands `clip_tree` a tree that `scrub_tree` has bounded, or a
#: flat dict of strings the server built itself (no depth to speak of).
KNOWN_SAFE_CALLERS = {
    # `clip_tree` calling itself and `bound_arguments` composing it.
    ("packages/postern-core/src/postern_core/store/audit.py", "clip_tree"),
    ("packages/postern-core/src/postern_core/store/audit.py", "bound_arguments"),
    # The api: `bound_arguments(_scrub(...))`, scrubbed first.
    ("services/api/middleware/audit.py", "_arguments"),
    # confirm, two functions of this name: the approval row (five fixed keys,
    # the caller's two values through `scrub_tree` in `services/confirm/audit.py`)
    # and the pairing row (strings the server built, one level deep).
    ("services/confirm/audit.py", "_arguments"),
    ("services/confirm/audit.py", "_with_assertion_jti"),
}


def test_every_caller_of_clip_tree_is_a_known_one_that_scrubs_first() -> None:
    found = _callers_of_the_clipper()
    unreviewed = found - KNOWN_SAFE_CALLERS
    assert unreviewed == set(), (
        "a new caller of clip_tree/bound_arguments: it recurses without a depth bound, "
        "so its tree must go through scrub_tree first; add it to KNOWN_SAFE_CALLERS once it does"
    )
    assert KNOWN_SAFE_CALLERS - found == set(), "a listed caller no longer exists; remove it"

"""A call the audit row cannot hold is refused before it runs, or it is audited.

The audit ENTRY row is written before the backend is reached and a failed write
fails the call closed (decision 0006). Three shapes of caller-chosen input made
that insert fail AFTER the request had been accepted, so the call ended as an
HTTP 200 carrying an error with no backend call and ZERO audit rows:

* a JSON-RPC ``id`` (or any other string) holding ``\\u0000``, which PostgreSQL
  refuses in a ``text`` column and in JSONB (``CharacterNotInRepertoireError``);
* a lone surrogate (``\\ud800``), which UTF-8 cannot encode
  (``UnicodeEncodeError``);
* ``arguments`` nested deeper than the interpreter's recursion limit, which
  raised ``RecursionError`` inside ``scrub_tree``.

The design, one behaviour per shape and stated here so a reader does not have
to infer it:

1. ``HeaderBodyValidation`` refuses with 400 / -32700 any body that holds, in a
   key or a value, at any depth, a string with U+0000 or a code point in
   U+D800-U+DFFF. The walk is iterative; a body with more than 1,000,000 nodes
   is refused as well.
2. Nesting depth is NOT refused by the middleware. A 9,000-deep ``arguments`` is
   valid JSON and reaches the tool; ``scrub_tree`` records the sentinel
   ``"[nested too deeply]"`` at depth 100 and the audit rows are written.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import httpx2
import pytest
from postern_core.domain.masking import SCRUB_MAX_DEPTH, TOO_DEEP, scrub_text, scrub_tree
from postern_core.identity import CustomerRef
from postern_core.json_strict import loads_finite_utf8
from postern_core.store.engine import Database
from postern_core.store.models import AuditEntry
from sqlalchemy import select
from starlette.types import Message, Receive, Scope, Send

from services.api.asgi import header_validation
from services.api.asgi.header_validation import HeaderBodyValidation, _storable
from services.api.main import create_app
from services.api.settings import Settings
from tests.fixtures import backend_responses as fx
from tests.fixtures.append_only_bypass import (
    delete_audit_rows_by_bypassing_the_append_only_triggers,
)

LEGACY: dict[str, str] = {}
MODERN = {"MCP-Protocol-Version": "2026-07-28"}
PROTOCOLS = [pytest.param(LEGACY, id="legacy"), pytest.param(MODERN, id="modern")]
MCP_HEADERS = {
    "Accept": "application/json, text/event-stream",
    "Content-Type": "application/json",
    "Mcp-Method": "tools/call",
    "Mcp-Name": "accounts.list",
}
PARSE_ERROR = (400, -32700, "Parse error")


ENVELOPE = (
    '"io.modelcontextprotocol/protocolVersion":"2026-07-28",'
    '"io.modelcontextprotocol/clientCapabilities":{}'
)


def _call(
    protocol: dict[str, str],
    *,
    id_: str = "1",
    arguments: str = "{}",
    meta_members: str = "",
) -> str:
    """A tools/call body; the 2026-07-28 path requires the envelope keys in `_meta`."""
    members = [m for m in (ENVELOPE if protocol else "", meta_members) if m]
    return (
        '{"jsonrpc":"2.0","id":' + id_ + ',"method":"tools/call",'
        '"params":{"name":"accounts.list","arguments":'
        + arguments
        + ',"_meta":{'
        + ",".join(members)
        + "}}}"
    )


async def _post(
    pg_url: str, raw: str, protocol: dict[str, str]
) -> tuple[httpx2.Response, list[str], list[AuditEntry]]:
    backend_paths: list[str] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        backend_paths.append(request.url.path)
        return httpx2.Response(200, json=fx.ACCOUNTS)

    app = create_app(
        Settings(backend_base_url="https://backend.test", database_url=pg_url),
        resolver=lambda: CustomerRef(value="cust_7f3a"),
        transport=httpx2.MockTransport(handler),
    )
    db = Database(pg_url)
    async with db.sessionmaker() as s:
        await delete_audit_rows_by_bypassing_the_append_only_triggers(s)
        await s.commit()
    try:
        async with app.router.lifespan_context(app):
            async with httpx2.AsyncClient(
                transport=httpx2.ASGITransport(app=app), base_url="http://test"
            ) as client:
                response = await client.post(
                    "/mcp", headers={**MCP_HEADERS, **protocol}, content=raw.encode()
                )
        async with db.sessionmaker() as s:
            rows = list((await s.execute(select(AuditEntry).order_by(AuditEntry.id))).scalars())
        return response, backend_paths, rows
    finally:
        async with db.sessionmaker() as s:
            await delete_audit_rows_by_bypassing_the_append_only_triggers(s)
            await s.commit()
        await db.close()


def _shape(response: httpx2.Response) -> tuple[int, int, str]:
    body = response.json()
    return response.status_code, body["error"]["code"], body["error"]["message"]


@pytest.mark.parametrize("protocol", PROTOCOLS)
async def test_control_a_plain_call_is_served_and_audited(
    pg_url: str, protocol: dict[str, str]
) -> None:
    """Without this the refusals below could be a request that never worked."""
    response, backend_paths, rows = await _post(pg_url, _call(protocol), protocol)

    assert response.status_code == 200, response.text
    assert backend_paths == ["/accounts"]
    assert len(rows) >= 1


UNSTORABLE: dict[str, Callable[[dict[str, str]], str]] = {
    "id-with-nul": lambda p: _call(p, id_='"a\\u0000"'),
    "id-with-lone-surrogate": lambda p: _call(p, id_='"\\ud800"'),
    "id-with-low-surrogate": lambda p: _call(p, id_='"\\udfff"'),
    "argument-value-with-nul": lambda p: _call(p, arguments='{"x":"a\\u0000b"}'),
    "argument-value-with-surrogate": lambda p: _call(p, arguments='{"x":"\\ud800"}'),
    "argument-key-with-nul": lambda p: _call(p, arguments='{"a\\u0000":1}'),
    "argument-key-with-surrogate": lambda p: _call(p, arguments='{"\\udc00":1}'),
    "meta-value-with-nul": lambda p: _call(p, meta_members='"x":"\\u0000"'),
    "meta-key-with-surrogate": lambda p: _call(p, meta_members='"\\ud83d":1'),
    "nested-in-list-in-arguments": lambda p: _call(p, arguments='{"x":[1,[{"k":["\\u0000"]}]]}'),
    "method-with-nul": lambda p: (
        '{"jsonrpc":"2.0","id":1,"method":"tools/call\\u0000","params":{"name":"accounts.list"}}'
    ),
}


@pytest.mark.parametrize("protocol", PROTOCOLS)
@pytest.mark.parametrize("name", sorted(UNSTORABLE))
async def test_a_string_the_audit_row_cannot_hold_is_refused_as_a_parse_error(
    pg_url: str, protocol: dict[str, str], name: str
) -> None:
    """Measured before the fix for the id cases: HTTP 200, no backend call, 0 rows."""
    response, backend_paths, rows = await _post(pg_url, UNSTORABLE[name](protocol), protocol)

    assert _shape(response) == PARSE_ERROR, response.text
    assert backend_paths == []
    assert rows == []


async def test_a_valid_surrogate_pair_and_ordinary_unicode_are_not_refused(pg_url: str) -> None:
    """A pair is ONE code point once decoded (U+1F600), not two surrogates."""
    response, backend_paths, rows = await _post(
        pg_url,
        # U+D7FF and U+E000 are the code points either side of the surrogate
        # block and are ordinary text: a range widened by one at either end
        # would refuse them.
        _call(LEGACY, meta_members='"x":"\\ud83d\\ude00 caf\\u00e9 \\ud7ff \\ue000"'),
        LEGACY,
    )

    assert response.status_code == 200, response.text
    assert backend_paths == ["/accounts"]
    assert len(rows) >= 1


@pytest.mark.parametrize("protocol", PROTOCOLS)
async def test_a_top_level_array_is_walked_too(pg_url: str, protocol: dict[str, str]) -> None:
    """A batch is refused downstream anyway, which is why a walk that skipped a
    top-level list would go unnoticed; the refusal is pinned here so it cannot
    start to matter. Same answer as the object form, on both protocols."""
    plain = await _post(pg_url, "[" + _call(protocol) + "]", protocol)
    assert plain[0].status_code != 400 or _shape(plain[0]) != PARSE_ERROR

    response, backend_paths, rows = await _post(
        pg_url, "[" + _call(protocol, id_='"\\u0000"') + "]", protocol
    )

    assert _shape(response) == PARSE_ERROR, response.text
    assert backend_paths == []
    assert rows == []


def _nested(depth: int) -> str:
    return '{"d":' * depth + "1" + "}" * depth


@pytest.mark.parametrize("depth", [1_000, 5_000, 9_000])
async def test_a_deeply_nested_arguments_tree_is_audited_not_dropped(
    pg_url: str, depth: int
) -> None:
    """Valid JSON for the stdlib, so it is not refused; the audit rows exist.

    Measured before the fix at 1,000 to 9,997 levels: -32603, 0 rows, no backend
    call, a RecursionError inside `scrub_tree`."""
    response, backend_paths, rows = await _post(
        pg_url, _call(MODERN, arguments=_nested(depth)), MODERN
    )

    assert rows, f"no audit row for a {depth}-deep call: {response.status_code} {response.text}"
    arguments = rows[0].arguments
    assert TOO_DEEP in repr(arguments)
    assert len(repr(arguments)) < 10_000
    if backend_paths:
        assert response.status_code == 200
        assert len(rows) >= 2


async def test_a_body_past_the_node_cap_is_refused_as_a_parse_error(
    pg_url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    from services.api.asgi import header_validation

    monkeypatch.setattr(header_validation, "MAX_WALK_NODES", 50)
    big = "[" + ",".join(["1"] * 200) + "]"
    response, backend_paths, rows = await _post(
        pg_url, _call(LEGACY, arguments='{"x":' + big + "}"), LEGACY
    )

    assert _shape(response) == PARSE_ERROR
    assert backend_paths == []
    assert rows == []


# ---------------------------------------------------------------------------
# scrub_tree: the bound.
# ---------------------------------------------------------------------------


def _chain(depth: int) -> Any:
    tree: Any = "leaf"
    for _ in range(depth):
        tree = {"d": tree}
    return tree


def test_scrub_tree_is_unchanged_up_to_the_bound() -> None:
    tree = _chain(SCRUB_MAX_DEPTH)
    assert scrub_tree(tree) == tree


def test_scrub_tree_cuts_one_level_past_the_bound_with_the_sentinel() -> None:
    cut = scrub_tree(_chain(SCRUB_MAX_DEPTH + 1))
    node: Any = cut
    for _ in range(SCRUB_MAX_DEPTH):
        node = node["d"]
    assert node == TOO_DEEP == "[nested too deeply]"


def test_scrub_tree_cuts_lists_too_and_keeps_siblings_outside_the_cut() -> None:
    deep: Any = [1]
    for _ in range(SCRUB_MAX_DEPTH + 5):
        deep = [deep]
    pan = "card 4111111111114417 here"
    out = scrub_tree({"keep": pan, "deep": deep, "n": 3})

    assert out["n"] == 3
    assert out["keep"] == scrub_text(pan) != pan
    node: Any = out["deep"]
    for _ in range(SCRUB_MAX_DEPTH - 1):
        node = node[0]
    assert node == TOO_DEEP


@pytest.mark.parametrize("depth", [1_000, 9_997, 200_000])
def test_scrub_tree_does_not_raise_on_any_depth(depth: int) -> None:
    tree: Any = 1
    for _ in range(depth):
        tree = [tree]
    assert TOO_DEEP in repr(scrub_tree({"a": tree}))


# ---------------------------------------------------------------------------
# The walk itself, and the REAL node cap.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        (chr(0xD7FF), True),
        (chr(0xE000), True),
        (chr(0xD800), False),
        (chr(0xDFFF), False),
        ("\x00", False),
    ],
)
def test_the_walk_accepts_the_code_points_either_side_of_the_surrogate_block(
    text: str, expected: bool
) -> None:
    """As a value, as a key, and nested in a list inside a dict."""
    assert _storable(text) is expected
    assert _storable({"k": text}) is expected
    assert _storable({text: 1}) is expected
    assert _storable({"a": [1, [{"b": [text]}]]}) is expected
    assert _storable([text]) is expected


def test_the_node_cap_is_one_million() -> None:
    assert header_validation.MAX_WALK_NODES == 1_000_000


async def _run(raw: bytes, max_body_bytes: int | None) -> tuple[int, list[bytes]]:
    """Drive the middleware with `raw`; return the status and what went downstream."""
    seen: list[bytes] = []
    statuses: list[int] = []

    async def downstream(scope: Scope, receive: Receive, send: Send) -> None:
        message = await receive()
        seen.append(message.get("body", b""))
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"{}"})

    async def receive() -> Message:
        return {"type": "http.request", "body": raw, "more_body": False}

    async def send(message: Message) -> None:
        if message["type"] == "http.response.start":
            statuses.append(message["status"])

    scope: Scope = {"type": "http", "method": "POST", "headers": []}
    await HeaderBodyValidation(downstream, max_body_bytes=max_body_bytes)(scope, receive, send)
    return statuses[0], seen


def _numbers(count: int) -> bytes:
    """A top-level array of `count` numbers: `count + 1` nodes, 2 bytes each."""
    return ("[" + ",".join(["0"] * count) + "]").encode()


@pytest.mark.parametrize(
    ("count", "status"), [(999_998, 200), (999_999, 200), (1_000_000, 400), (1_000_001, 400)]
)
async def test_the_real_node_cap_refuses_exactly_past_one_million_nodes(
    count: int, status: int
) -> None:
    """Not monkeypatched: 999,999 numbers plus the array is 1,000,000 nodes and
    passes, one more is refused. A cap of 10**9 passes all four."""
    raw = _numbers(count)
    got, seen = await _run(raw, max_body_bytes=4 * 1024 * 1024)

    assert got == status
    assert (seen == [raw]) is (status == 200)
    if status == 400:
        assert loads_finite_utf8(raw)  # it parsed: the refusal is the cap, not the parser


async def test_the_cap_never_fires_at_the_default_body_limit() -> None:
    """The largest all-numbers body 1 MiB holds is about 524,000 nodes."""
    limit = 1_048_576
    count = (limit - 1) // 2
    raw = _numbers(count)
    assert len(raw) <= limit
    got, seen = await _run(raw, max_body_bytes=limit)
    assert got == 200 and seen == [raw]

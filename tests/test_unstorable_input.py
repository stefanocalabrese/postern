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
from postern_core.store.engine import Database
from postern_core.store.models import AuditEntry
from sqlalchemy import select

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
        pg_url, _call(LEGACY, meta_members='"x":"\\ud83d\\ude00 caf\\u00e9"'), LEGACY
    )

    assert response.status_code == 200, response.text
    assert backend_paths == ["/accounts"]
    assert len(rows) >= 1


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

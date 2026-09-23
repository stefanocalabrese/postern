"""`audit_log.arguments` is bounded, so a `tools/call` cannot fill the volume.

`arguments` is `JSONB`, and until the bound this file pins it was the one
column on the row with no ceiling of any kind. The three `VARCHAR` columns
beside it each have one, because an over-wide value makes the INSERT raise;
JSONB refuses nothing, so the absence of a width to overflow read as the
absence of a reason to bound.

The reason is not the column, it is the disk, and the amplifier is the
fail-closed policy in `dev-docs/decisions/0006-audit-write-failure.md`. One
authenticated call carrying 1,037,473 characters of incompressible base64 in
an argument wrote 1,909,922 bytes to `audit_log` -- 954,961 per row, because
BOTH rows of the call carry the same tree. A thousand such calls write 1.78
GiB. There is no retention job, no partitioning and no `DELETE` in production
code, so the table only grows; when the volume fills, the audit INSERT fails,
and a failed audit write takes the tool call with it. Every call, every
customer, for a few thousand requests of attacker cost. With the bound, the
same call writes 1,172 bytes.

WHAT IS PINNED HERE, and the split from the two existing audit test files
matters. `tests/test_audit_middleware.py` and `tests/test_audit_entry_row.py`
own the row's shape and the two-row protocol, and both pass UNEDITED across
this change -- which is itself the evidence that an ordinary call is
untouched, since between them they assert the exact `arguments` value of
every call they make. This file owns only the bound: that it fires, what it
leaves behind when it does, that it reaches both rows, and that it does
nothing at all below the limit.
"""

import asyncio
import base64
import json
import random
from collections.abc import AsyncIterator
from typing import Any

import httpx2
import pytest_asyncio
from fastmcp import Client, FastMCP
from postern_core.domain.masking import redaction_budget
from postern_core.facade.client import BackendClient
from postern_core.identity import CustomerRef
from postern_core.store.engine import Database
from postern_core.store.models import AuditEntry
from sqlalchemy import delete, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from services.api.middleware.audit import (
    _ARGUMENTS_TRUNCATED_KEY,
    _MAX_ARGUMENT_VALUE,
    _MAX_ARGUMENTS_BYTES,
    _TRUNCATED,
    AuditMiddleware,
    _arguments,
    _cap_arguments,
    _clip_tree,
    record_data_touch,
)

CUSTOMER = CustomerRef(value="cust_capcheck")

# 1 MiB, the ceiling `settings.max_body_bytes` puts on a whole request body
# and therefore the most one argument can carry today.
#
# MIME-WRAPPED base64, at RFC 2045's 76-character line width, rather than one
# unbroken run -- and the difference is the whole reason this constant has a
# comment. An unbroken alphanumeric run longer than `masking`'s
# `_IBAN_SCAN_MAX_TOKEN` (128) is already bare-masked to `••••` by the scrub,
# so a naive `"QUJDREVG" * N` fixture arrives at this bound as four
# characters and tests nothing at all -- measured, on the first version of
# this file, where six tests passed for that reason and not for the right
# one. Real base64 is line-wrapped and its own alphabet contains `+` and `/`,
# both of which end a token, so its runs are short, the scrub leaves it
# alone, and all 1 MiB of it reaches the column. That is the shape the defect
# was measured against.
# INCOMPRESSIBLE, from a seeded PRNG rather than one line repeated. TOAST
# compresses a JSONB value before storing it and `pg_column_size` reports the
# compressed width, so a fixture of 13,600 identical lines measures at 24 KB
# on disk and understates the defect by seventy-fold -- measured, on the
# first version of this file. Distinct random bytes per line is what an
# attacker actually sends when the goal is bytes on disk.
_RNG = random.Random(20260923)  # noqa: S311 -- a test fixture's bytes, not a key
_B64 = base64.b64encode(_RNG.randbytes(768_000)).decode()
ONE_MIB = "\n".join(_B64[i : i + 76] for i in range(0, len(_B64), 76))
assert 1_000_000 < len(ONE_MIB) <= 1_048_576, len(ONE_MIB)


def _scrubbed_and_bounded(raw: dict[str, Any]) -> dict[str, Any]:
    """`_arguments` as `on_call_tool` calls it: inside one redaction budget."""
    with redaction_budget():
        return _arguments(raw)


def _json_bytes(tree: Any) -> int:
    return len(json.dumps(tree, ensure_ascii=False).encode())


# ---------------------------------------------------------------------------
# The bound itself, no database
# ---------------------------------------------------------------------------


def test_a_normal_call_is_untouched() -> None:
    """The invariant that matters most, and the one a bound is most likely to
    break: an ordinary argument tree comes back the same object's worth of
    data, key for key and character for character, with no marker anywhere.

    A marker on an ordinary call would be the row lying about itself, which
    is the failure `_clamp`'s own docstring refuses for `tool_name`. Every
    tree here is one a registered tool in this repository actually produces.
    """
    for tree in (
        {},
        {"amount": 50},
        {"amount": 50, "memo": "coffee"},
        {"account_ref": "acc_" + "x" * 61},
        {"account_ref": "acc_" + "x" * 61, "days": 365},
        {"nested": {"a": [1, 2, {"b": "c"}]}, "flag": True, "nothing": None},
    ):
        assert _scrubbed_and_bounded(tree) == tree, tree
        assert _TRUNCATED not in json.dumps(tree), tree


def test_an_over_limit_value_is_clipped_and_its_siblings_survive() -> None:
    """The cheap attack, and the reason the per-value bound exists at all.

    One junk value beside a real one. A tree-only bound would drop both and
    hand the attacker the erasure of the very argument an investigator wants;
    the per-value bound keeps `account_ref` exactly as sent and marks only
    the junk.
    """
    out = _scrubbed_and_bounded({"account_ref": "acc_12345", "junk": ONE_MIB})

    assert out["account_ref"] == "acc_12345", "a real argument was lost to its noisy sibling"
    assert len(out["junk"]) == _MAX_ARGUMENT_VALUE
    assert out["junk"].endswith(_TRUNCATED), "a clipped value must say so"
    assert _ARGUMENTS_TRUNCATED_KEY not in out, "the tree bound should not have fired here"
    assert _json_bytes(out) <= _MAX_ARGUMENTS_BYTES


def test_keys_are_bounded_as_well_as_values() -> None:
    """A key is exactly as caller-chosen as a value, so bounding only values
    leaves `{"<1 MiB of junk>": 1}` as an equally good way to fill the
    column."""
    out = _scrubbed_and_bounded({ONE_MIB: 1})

    (key,) = out
    assert len(key) == _MAX_ARGUMENT_VALUE
    assert key.endswith(_TRUNCATED)


def test_an_over_limit_tree_becomes_a_recognisable_marker() -> None:
    """The attack the per-value bound cannot reach: many keys, each one
    individually unremarkable.

    The replacement has to be valid JSON a query can find, because the column
    is JSONB and nothing is gained by a marker an investigator cannot filter
    on.
    """
    tree = {f"k{i:05d}": "v" * 100 for i in range(10_000)}
    out = _scrubbed_and_bounded(tree)

    marker = out[_ARGUMENTS_TRUNCATED_KEY]
    assert marker["original_bytes"] > _MAX_ARGUMENTS_BYTES
    assert marker["limit_bytes"] == _MAX_ARGUMENTS_BYTES
    assert marker["kept_keys"] + marker["dropped_keys"] == 10_000, marker
    assert marker["dropped_keys"] > 0
    assert marker["kept_keys"] > 0, "a first-fit prefix should keep what fits"
    assert _json_bytes(out) <= _MAX_ARGUMENTS_BYTES
    # Valid JSON, and a JSONB containment predicate can find it.
    assert _ARGUMENTS_TRUNCATED_KEY in json.loads(json.dumps(out))


def test_a_value_that_is_not_a_string_is_caught_by_the_tree_bound() -> None:
    """`scrub_tree` returns an `int` unchanged and so does `_clip_tree`, by
    design -- neither can carry a PAN that the masking patterns match, and
    coercing them to text to find out would change what the caller stores.
    So numbers have no per-value bound at all, and the tree bound is the only
    thing between `{"n": [<a thousand 300-digit integers>]}` and the column.
    """
    out = _scrubbed_and_bounded({"account_ref": "acc_12345", "n": [10**300] * 1000})

    assert out["account_ref"] == "acc_12345", "the small real argument should survive"
    assert "n" not in out
    marker = out[_ARGUMENTS_TRUNCATED_KEY]
    assert marker["dropped_keys"] == 1
    assert marker["kept_keys"] == 1
    assert marker["original_bytes"] > _MAX_ARGUMENTS_BYTES
    assert _json_bytes(out) <= _MAX_ARGUMENTS_BYTES


def test_clipping_reaches_values_nested_in_lists_and_dicts() -> None:
    """Arguments are an arbitrary JSON tree, not a flat map, so a bound that
    only looked at the top level would be bypassed by one level of nesting."""
    out = _clip_tree({"a": [{"b": ["x" * 5000]}]})

    assert len(out["a"][0]["b"][0]) == _MAX_ARGUMENT_VALUE
    assert out["a"][0]["b"][0].endswith(_TRUNCATED)


def test_the_bound_cannot_itself_raise() -> None:
    """A bound that exists to stop an outage must not be able to cause one:
    anything raised here lands in `on_call_tool` before either row is written,
    and a failed audit write takes the tool call with it.

    `{"n": 10**100000}` is the case that found this. `default=str` covers an
    unserialisable TYPE and does nothing for a serialisable type that raises
    while being written, which Python 3.12 has one of: `int.__str__` refuses
    past `sys.get_int_max_str_digits()` and raises `ValueError`. The first
    version of `_cap_arguments` raised it straight through, which would have
    been a tool-call outage caused by the bound meant to prevent one.

    Unmeasurable is treated as OVER the limit, never under: a tree whose size
    cannot be established cannot be stored safely either. `dropped_bytes` is
    `null` on that path rather than a fabricated number.
    """
    huge_int = _cap_arguments({"n": 10**100_000})
    marker = huge_int[_ARGUMENTS_TRUNCATED_KEY]
    assert marker["original_bytes"] is None, "an unmeasurable tree must not invent a number"
    assert marker["dropped_keys"] == 1
    assert marker["kept_keys"] == 0
    assert json.loads(json.dumps(huge_int))[_ARGUMENTS_TRUNCATED_KEY]["original_bytes"] is None

    # An unserialisable TYPE takes the `default=str` path and is measurable,
    # so a small one is left exactly as it arrived.
    unserialisable = {"x": object()}
    assert _cap_arguments(unserialisable) is unserialisable


def test_the_marker_is_forgeable_and_only_in_the_harmless_direction() -> None:
    """Stated because the docstring on `_ARGUMENTS_TRUNCATED_KEY` claims it,
    and a claim about a security property belongs in a test.

    A caller can name an argument `postern.arguments_truncated`, so a query
    filtering on that key can match a row that lost nothing. What it cannot
    do is the reverse: a row that really was capped always carries the key,
    because the capped tree is built by `_cap_arguments` and holds nothing
    the caller chose.
    """
    forged = _scrubbed_and_bounded({_ARGUMENTS_TRUNCATED_KEY: "not a marker", "real": "value"})
    assert forged[_ARGUMENTS_TRUNCATED_KEY] == "not a marker"
    assert forged["real"] == "value", "nothing was actually dropped from this row"

    # A row that really was capped always carries the key, and carries it as
    # the marker object rather than whatever the caller sent -- the marker is
    # written last and wins the collision.
    junk = {f"k{i:05d}": "v" * 100 for i in range(10_000)}
    capped = _scrubbed_and_bounded({_ARGUMENTS_TRUNCATED_KEY: "not a marker"} | junk)
    assert set(capped[_ARGUMENTS_TRUNCATED_KEY]) == {
        "original_bytes",
        "limit_bytes",
        "dropped_keys",
        "kept_keys",
    }


def test_the_bound_runs_after_masking_not_before() -> None:
    """Ordering, pinned by its consequence. `_clamp` appends `_TRUNCATED`,
    and `_scrub` reaches `masking._strip_invisible`, which deletes characters
    outright -- so a marker written before the scrub would depend on another
    package's strip set to survive. Running the clip afterwards also means a
    PAN inside the kept prefix is still masked rather than clipped past.
    """
    # Padded with short, separated tokens so the scrub leaves the padding
    # alone: an unbroken run would be bare-masked to `••••` and the value
    # would never reach the clip at all.
    out = _scrubbed_and_bounded({"memo": "card 4111111111111111 " + "pad " * 3000})

    assert "4111111111111111" not in out["memo"], "the PAN survived the clip"
    assert "•••• 1111" in out["memo"]
    assert len(out["memo"]) == _MAX_ARGUMENT_VALUE
    assert out["memo"].endswith(_TRUNCATED)


# ---------------------------------------------------------------------------
# Both rows of one call, against a real database
# ---------------------------------------------------------------------------


def _minter(customer: CustomerRef, audience: str) -> str:
    return "test-token"


def _backend(database: Database) -> BackendClient:
    def handler(request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(200, json={"accounts": []})

    return BackendClient(
        "https://backend.test",
        _minter,
        transport=httpx2.MockTransport(handler),
        before_backend_request=record_data_touch,
    )


@pytest_asyncio.fixture
async def capped_server(database: Database) -> AsyncIterator[FastMCP]:
    """A server whose one tool reaches the backend, so every call writes the
    `reaching` row as well as the completion row. Both carry `arguments`, and
    the bound has to be on both."""
    async with database.sessionmaker() as s:
        await s.execute(delete(AuditEntry))
        await s.commit()

    backend = _backend(database)
    mcp = FastMCP(name="arguments-cap-test")
    mcp.add_middleware(AuditMiddleware(database))

    @mcp.tool
    async def touches_backend(memo: str = "", account_ref: str = "") -> str:
        await backend.get_json("/accounts", customer=CUSTOMER)
        return "ok"

    yield mcp

    async with database.sessionmaker() as s:
        await s.execute(delete(AuditEntry))
        await s.commit()


async def _rows(session: AsyncSession) -> list[AuditEntry]:
    result = await session.execute(select(AuditEntry).order_by(AuditEntry.id))
    return list(result.scalars().all())


async def test_both_rows_of_one_call_carry_the_bound(
    capped_server: FastMCP, session: AsyncSession
) -> None:
    """The verification that cannot be done by reading the code: the
    `reaching` row is written from the facade hook inside the tool body and
    the completion row after it returns, through two different code paths,
    and a bound applied to one of them would be no bound at all.

    `pg_column_size` rather than a Python measurement, because what is being
    claimed is about the row on disk.
    """
    async with Client(transport=capped_server) as c:
        await c.call_tool("touches_backend", {"memo": ONE_MIB, "account_ref": "acc_12345"})

    rows = await _rows(session)
    assert [r.outcome for r in rows] == ["reaching", "returned"], [r.outcome for r in rows]

    for row in rows:
        assert row.arguments["account_ref"] == "acc_12345", row.outcome
        assert len(row.arguments["memo"]) == _MAX_ARGUMENT_VALUE, row.outcome
        assert row.arguments["memo"].endswith(_TRUNCATED), row.outcome

    # The two rows carry the identical tree, which is what makes one bound
    # at the point of construction sufficient for both.
    assert rows[0].arguments == rows[1].arguments

    sizes = await session.execute(
        text("SELECT pg_column_size(arguments) FROM audit_log ORDER BY id")
    )
    on_disk = [size for (size,) in sizes]
    assert len(on_disk) == 2
    for size in on_disk:
        assert size <= _MAX_ARGUMENTS_BYTES, f"a row reached {size} bytes on disk"


async def test_an_ordinary_call_stores_exactly_what_it_sent(
    capped_server: FastMCP, session: AsyncSession
) -> None:
    """The regression guard on the other side of the bound, against the real
    column rather than the helper: nothing ordinary may be altered, on either
    row, by so much as a character."""
    sent = {"memo": "Transferencia nomina mensual", "account_ref": "acc_12345"}
    async with Client(transport=capped_server) as c:
        await c.call_tool("touches_backend", sent)

    rows = await _rows(session)
    assert [r.arguments for r in rows] == [sent, sent]


async def test_a_thousand_maximal_calls_stay_bounded(
    capped_server: FastMCP, session: AsyncSession
) -> None:
    """The claim the bound is actually for, expressed as the number it
    changes rather than as the mechanism.

    One such call wrote 1,909,922 bytes across its two rows before this bound
    and 1,172 after, both measured on this exact fixture against this exact
    column. This runs ten of them and extrapolates from what they really
    wrote on disk, rather than asserting the ratio from the constants.
    """
    async with Client(transport=capped_server) as c:
        for _ in range(10):
            await c.call_tool("touches_backend", {"memo": ONE_MIB})

    total = await session.execute(text("SELECT SUM(pg_column_size(arguments)) FROM audit_log"))
    ten_calls = total.scalar_one()
    assert ten_calls is not None
    per_call = ten_calls / 10
    assert per_call <= 2 * _MAX_ARGUMENTS_BYTES, per_call
    # 1,909,922 bytes per call was the measured cost of this exact shape
    # before the bound. Anything within two orders of magnitude of it is a
    # regression, whatever the constants happen to say.
    assert per_call < 1_909_922 / 100, per_call


async def test_concurrent_calls_do_not_share_a_tree(
    capped_server: FastMCP, session: AsyncSession
) -> None:
    """`_arguments` builds a fresh tree per call and the marker object is
    constructed rather than shared, so two calls in flight cannot end up
    naming each other's arguments -- the failure a module-level default
    would produce."""
    async with Client(transport=capped_server) as c:
        await asyncio.gather(
            c.call_tool("touches_backend", {"memo": "first"}),
            c.call_tool("touches_backend", {"memo": "second"}),
        )

    memos = {row.arguments["memo"] for row in await _rows(session)}
    assert memos == {"first", "second"}, memos


async def test_the_logical_width_is_bounded_not_just_the_compressed_one(
    capped_server: FastMCP, session: AsyncSession
) -> None:
    """`pg_column_size` reports the width AFTER TOAST compression, so on its
    own it can report a bounded row for an unbounded value -- a 1 MiB tree of
    repetitive text compresses to about 24 KB and looks almost respectable.
    What actually has to be bounded is the value, so this measures the
    uncompressed JSON text as well.
    """
    async with Client(transport=capped_server) as c:
        await c.call_tool("touches_backend", {"memo": ONE_MIB})

    widths = await session.execute(
        text("SELECT octet_length(arguments::text), pg_column_size(arguments) FROM audit_log")
    )
    rows = list(widths)
    assert len(rows) == 2, rows
    for logical, on_disk in rows:
        assert logical <= _MAX_ARGUMENTS_BYTES, f"{logical} bytes of JSON text"
        assert on_disk <= _MAX_ARGUMENTS_BYTES, f"{on_disk} bytes on disk"
        # An ABSOLUTE ceiling as well as the constant's own, because a test
        # that only ever compares a row against the constant that produced it
        # cannot fail when that constant is wrong -- it passed unchanged with
        # both bounds raised to a terabyte, which is the unbounded behaviour
        # this whole file exists to catch. 64 KiB is far above any bound this
        # column should ever carry and far below the 954,961 bytes one row of
        # this exact call wrote before the fix.
        assert logical < 65_536, f"{logical} bytes of JSON text is not a bounded row"
        assert on_disk < 65_536, f"{on_disk} bytes on disk is not a bounded row"

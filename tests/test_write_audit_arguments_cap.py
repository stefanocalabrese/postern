"""``audit_log.arguments`` is bounded on the WRITE path too, so an approval
cannot fill the volume.

``1a97160`` bounded the read path and deliberately left this one alone. The
write path's exposure to the same defect is strictly worse, on two counts
measured against this column on 2026-09-24 rather than argued:

1. NO BODY LIMIT. ``services/api`` wires ``HeaderBodyValidation`` with
   ``max_body_bytes``, which capped the read-path attack at 1 MiB.
   ``services/confirm/main.py``'s ``create_confirm_app`` wires no body-size
   middleware at all. A 404 carrying 10,131,578 characters in
   ``confirming_device`` wrote 7,742,315 bytes on disk in ONE row.
2. A ROW ON EVERY REFUSED PATH. A completion row is written for every
   approval attempt past a verified subject and a non-empty challenge id, so
   404, 409 and 410 each write one. An authenticated caller therefore needs
   NO valid challenge: a 404 aimed at an id naming nothing, carrying 1 MiB,
   wrote 979,108 bytes on disk and 992,895 bytes of JSON text. There is no
   challenge to create, no race to win and no expiry to beat.

Both services share the database and both fail closed
(``dev-docs/decisions/0006-audit-write-failure.md``), so a volume filled from
here takes down every tool call in ``services/api`` as well as every approval.
After the bound the same four requests write 687, 691, 691 and 1,378 bytes.

WHAT IS PINNED HERE, and the split from ``tests/test_write_audit.py`` mirrors
the one ``tests/test_audit_arguments_cap.py`` made on the read path. That file
owns the row's shape and the two-row protocol, and it passes UNEDITED across
this change -- which is itself the evidence that an ordinary approval is
untouched, since
``tests/test_write_audit.py::test_the_arguments_column_points_at_the_challenge_without_copying_it``
asserts the exact five-key tree of the approval it makes. This file owns only
the bound: that it fires, what it leaves behind when it does, that it reaches
the refused paths as well as the successful one, that it does nothing at all
below the limit, and that its marker is the same shape the read path writes.
"""

import base64
import json
import os
import random
from collections.abc import AsyncGenerator, Generator
from typing import Any

import pytest
from fastmcp.server.auth.providers.jwt import JWTVerifier, RSAKeyPair
from postern_core.domain.masking import redaction_budget
from postern_core.store.audit import (
    ARGUMENTS_TRUNCATED_KEY,
    MAX_ARGUMENT_VALUE,
    MAX_ARGUMENTS_BYTES,
    TRUNCATED,
)
from postern_core.store.engine import Database
from postern_core.store.models import AuditEntry, ChallengeRecord
from sqlalchemy import delete, text
from starlette.applications import Starlette

from services.api.middleware.audit import _arguments as read_path_arguments
from services.confirm.audit import APPROVE_ROUTE
from services.confirm.audit import _arguments as write_path_arguments
from services.confirm.main import create_confirm_app
from services.confirm.settings import ConfirmSettings
from tests.test_write_audit import (
    AUDIENCE,
    ISSUER,
    OWNER,
    Backend,
    backend,  # noqa: F401 -- a fixture, used by name in every signature below
    bearer,
    post,
    rows,
    seed,
)

# 1 MiB of incompressible, MIME-wrapped base64, the fixture shape
# `tests/test_audit_arguments_cap.py` arrived at the hard way and whose two
# lessons both apply here unchanged.
#
# WRAPPED at RFC 2045's 76-character line width rather than one unbroken run:
# an unbroken alphanumeric run longer than `masking`'s `_IBAN_SCAN_MAX_TOKEN`
# (128) is already bare-masked to `••••` by the scrub, so a naive fixture
# arrives at this bound as four characters and tests nothing at all.
#
# INCOMPRESSIBLE, from a seeded PRNG rather than one line repeated: TOAST
# compresses a JSONB value before storing it and `pg_column_size` reports the
# compressed width, so a repetitive fixture understates the defect by
# seventy-fold. Distinct random bytes is what an attacker sends when the goal
# is bytes on disk.
_RNG = random.Random(20260924)  # noqa: S311 -- a test fixture's bytes, not a key
_B64 = base64.b64encode(_RNG.randbytes(786_000)).decode()
ONE_MIB = "\n".join(_B64[i : i + 76] for i in range(0, len(_B64), 76))
assert 1_000_000 < len(ONE_MIB) <= 1_100_000, len(ONE_MIB)

# Far above any bound this column should ever carry, and far below the 979,108
# bytes one refused approval wrote before the fix. Asserted alongside every
# comparison against `MAX_ARGUMENTS_BYTES` for the reason the read path's own
# file records: a test that only ever compares a row against the constant that
# produced it cannot fail when that constant is wrong. The read path's version
# of these assertions passed unchanged with both bounds raised to a terabyte.
ABSOLUTE_CEILING = 65_536


# ---------------------------------------------------------------------------
# Fixtures. A module-scoped container, mirroring `tests/test_write_audit.py`'s
# own rather than the session-scoped one in `tests/conftest.py`: these tests
# write megabyte rows and truncate two tables around every case, and the
# session container is shared with every read-path test that reads
# `audit_log`.
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def pg_url() -> Generator[str]:
    """Restores ``POSTERN_DATABASE_URL`` on the way out: leaving it pointed at
    a container about to be torn down would poison every ``from_env()`` call
    in whatever module runs next."""
    import docker
    from testcontainers.community.postgres import PostgresContainer

    try:
        docker.from_env().ping()
    except docker.errors.DockerException as exc:
        pytest.skip(f"Docker is not reachable, skipping write-audit cap tests: {exc}")

    previous = os.environ.get("POSTERN_DATABASE_URL")
    with PostgresContainer("postgres:17-alpine", driver="asyncpg") as pg:
        url = pg.get_connection_url()
        os.environ["POSTERN_DATABASE_URL"] = url
        from alembic import command
        from alembic.config import Config

        cfg = Config("alembic.ini")
        cfg.set_main_option("sqlalchemy.url", url)
        command.upgrade(cfg, "head")
        try:
            yield url
        finally:
            if previous is None:
                os.environ.pop("POSTERN_DATABASE_URL", None)
            else:
                os.environ["POSTERN_DATABASE_URL"] = previous


@pytest.fixture()
def settings(pg_url: str) -> ConfirmSettings:
    return ConfirmSettings(backend_base_url="https://backend.test", database_url=pg_url)


@pytest.fixture()
def db(settings: ConfirmSettings) -> Database:
    return Database(settings.database_url)


@pytest.fixture()
async def clean(db: Database) -> AsyncGenerator[Database, None]:
    """Both tables empty before AND after: these rows are committed through
    their own sessions and no rollback reaches them."""
    await _wipe(db)
    yield db
    await _wipe(db)


async def _wipe(db: Database) -> None:
    async with db.sessionmaker() as s:
        await s.execute(delete(AuditEntry))
        await s.execute(delete(ChallengeRecord))
        await s.commit()


@pytest.fixture(scope="module")
def key_pair() -> RSAKeyPair:
    return RSAKeyPair.generate()


@pytest.fixture()
def app(settings: ConfirmSettings, key_pair: RSAKeyPair) -> Starlette:
    verifier = JWTVerifier(public_key=key_pair.public_key, issuer=ISSUER, audience=AUDIENCE)
    return create_confirm_app(settings, assertion_verifier=verifier)


def _bounded(tree: dict[str, Any]) -> dict[str, Any]:
    """``_arguments`` as ``ApprovalAudit.__init__`` calls it: inside one
    redaction budget, which its docstring requires and which a second private
    scope would buy a fresh checksum allowance from."""
    with redaction_budget():
        return write_path_arguments(tree.pop("challenge_id", "chal_x"), tree)


async def _widths(db: Database) -> list[tuple[int, int]]:
    """``(on disk after TOAST, uncompressed JSON text)`` per row, in order.

    Both, never one. ``pg_column_size`` reports the width AFTER TOAST
    compression, so on its own it can report a bounded row for an unbounded
    value; ``octet_length(arguments::text)`` is the value's own size and is
    what actually has to be bounded.
    """
    async with db.sessionmaker() as s:
        result = await s.execute(
            text(
                "SELECT pg_column_size(arguments), octet_length(arguments::text) "
                "FROM audit_log ORDER BY id"
            )
        )
        return [(on_disk, logical) for on_disk, logical in result]


def _assert_bounded(widths: list[tuple[int, int]]) -> None:
    for on_disk, logical in widths:
        assert logical <= MAX_ARGUMENTS_BYTES, f"{logical} bytes of JSON text"
        assert on_disk <= MAX_ARGUMENTS_BYTES, f"{on_disk} bytes on disk"
        assert logical < ABSOLUTE_CEILING, f"{logical} bytes of JSON text is not a bounded row"
        assert on_disk < ABSOLUTE_CEILING, f"{on_disk} bytes on disk is not a bounded row"


# ---------------------------------------------------------------------------
# The bound itself, no database.
# ---------------------------------------------------------------------------


def test_an_ordinary_approval_is_untouched() -> None:
    """The invariant that matters most, and the one a bound is most likely to
    break: an ordinary approval body comes back the same five keys, character
    for character, with no marker anywhere.

    A marker on an ordinary approval would be the row lying about itself.
    """
    out = _bounded(
        {
            "challenge_id": "chal_args_001",
            "signature": "sig_x",
            "confirming_device": "pixel-9",
            "verification_result": "match_ok",
        }
    )

    assert out == {
        "route": APPROVE_ROUTE,
        "challenge_id": "chal_args_001",
        "signature_present": True,
        "confirming_device": "pixel-9",
        "verification_result": "match_ok",
    }
    assert TRUNCATED not in json.dumps(out)
    assert ARGUMENTS_TRUNCATED_KEY not in out


def test_an_absent_body_is_untouched() -> None:
    """The app sends neither optional field on a tier-1 approval, so the
    all-``None`` tree is the common case rather than an edge one."""
    out = _bounded({"challenge_id": "chal_bare"})

    assert out == {
        "route": APPROVE_ROUTE,
        "challenge_id": "chal_bare",
        "signature_present": False,
        "confirming_device": None,
        "verification_result": None,
    }


def test_an_over_limit_device_is_clipped_and_the_other_keys_survive() -> None:
    """The cheap attack, and the reason the per-value bound exists at all.

    A tree-only bound would drop `confirming_device` whole and mark the row;
    the per-value bound clips it to a prefix instead, so the row still records
    the first 511 characters of what the caller actually sent. Everything that
    identifies the request is untouched.
    """
    out = _bounded(
        {
            "challenge_id": "chal_clip",
            "signature": "sig_x",
            "confirming_device": ONE_MIB,
            "verification_result": "match_ok",
        }
    )

    assert out["route"] == APPROVE_ROUTE
    assert out["challenge_id"] == "chal_clip"
    assert out["signature_present"] is True
    assert out["verification_result"] == "match_ok"
    assert len(out["confirming_device"]) == MAX_ARGUMENT_VALUE
    assert out["confirming_device"].endswith(TRUNCATED), "a clipped value must say so"
    assert ARGUMENTS_TRUNCATED_KEY not in out, "the tree bound should not have fired here"
    assert len(json.dumps(out, ensure_ascii=False).encode()) <= MAX_ARGUMENTS_BYTES


def test_the_tree_bound_keeps_the_keys_that_identify_the_request() -> None:
    """The attack the per-value bound cannot reach: a caller-supplied SUB-TREE
    of many keys, each one individually unremarkable.

    This is where the key order in ``_arguments`` earns its comment. First-fit
    keeps top-level entries while they fit, and the three server-chosen keys
    are listed first, so what survives is exactly what an investigator needs
    to identify the request -- which route, which challenge, whether a
    signature was present -- and what is dropped is exactly the two fields
    that carried the junk.
    """
    out = _bounded(
        {
            "challenge_id": "chal_tree",
            "signature": "sig_x",
            "confirming_device": {f"k{i:05d}": "v" * 100 for i in range(10_000)},
            "verification_result": "match_ok",
        }
    )

    assert out["route"] == APPROVE_ROUTE
    assert out["challenge_id"] == "chal_tree"
    assert out["signature_present"] is True
    assert "confirming_device" not in out
    assert "verification_result" not in out

    marker = out[ARGUMENTS_TRUNCATED_KEY]
    assert marker["original_bytes"] > MAX_ARGUMENTS_BYTES
    assert marker["limit_bytes"] == MAX_ARGUMENTS_BYTES
    assert marker["kept_keys"] == 3
    assert marker["dropped_keys"] == 2
    assert marker["kept_keys"] + marker["dropped_keys"] == 5, "the tree has five keys"
    assert len(json.dumps(out, ensure_ascii=False).encode()) <= MAX_ARGUMENTS_BYTES
    # Valid JSON, and a JSONB containment predicate can find it.
    assert ARGUMENTS_TRUNCATED_KEY in json.loads(json.dumps(out))


def test_a_value_that_is_not_a_string_is_caught_by_the_tree_bound() -> None:
    """Masking returns an `int` unchanged and so does the clip, by design --
    neither can carry a PAN that the masking patterns match. So numbers have
    no per-value bound at all, and the tree bound is the only thing between
    ``{"verification_result": [<a thousand 300-digit integers>]}`` and the
    column."""
    out = _bounded(
        {
            "challenge_id": "chal_ints",
            "signature": "sig_x",
            "verification_result": [10**300] * 1000,
        }
    )

    assert out["challenge_id"] == "chal_ints", "the identifying keys should survive"
    assert "verification_result" not in out
    assert out[ARGUMENTS_TRUNCATED_KEY]["original_bytes"] > MAX_ARGUMENTS_BYTES
    assert len(json.dumps(out, ensure_ascii=False).encode()) <= MAX_ARGUMENTS_BYTES


def test_masking_still_runs_before_the_clip() -> None:
    """Ordering, pinned by its consequence. The clip appends ``TRUNCATED``,
    and the scrub reaches ``masking._strip_invisible``, which deletes
    characters outright -- so a marker written before the scrub would depend
    on another module's strip set to survive. Running the clip afterwards also
    means a PAN inside the kept prefix is still masked rather than clipped
    past.

    Padded with short, separated tokens so the scrub leaves the padding alone:
    an unbroken run would be bare-masked to ``••••`` and the value would never
    reach the clip at all.
    """
    out = _bounded(
        {
            "challenge_id": "chal_pan",
            "confirming_device": "card 4111111111111111 " + "pad " * 3000,
        }
    )

    assert "4111111111111111" not in out["confirming_device"], "the PAN survived the clip"
    assert "•••• 1111" in out["confirming_device"]
    assert len(out["confirming_device"]) == MAX_ARGUMENT_VALUE
    assert out["confirming_device"].endswith(TRUNCATED)


def test_an_enumeration_probe_clips_its_own_challenge_id() -> None:
    """``challenge_id`` comes off the URL path, so it is caller-chosen too and
    is bounded like everything else. The cost is nil: ``challenges
    .challenge_id`` is ``String(36)``, so an id past 512 characters can name
    no challenge that exists, and the only thing clipped is an enumeration
    probe -- which still records its own prefix and says it was cut.

    SEGMENTED, because an UNBROKEN alphanumeric run never reaches the clip at
    all: ``masking``'s ``_IBAN_SCAN_MAX_TOKEN`` is 128, and a longer run is
    bare-masked to ``••••`` without a checksum being spent on it. Both
    behaviours are asserted, because both are live and the second one is the
    surprising one -- an over-long unbroken id records four characters and
    names nobody, which is masking's decision and not this bound's.
    """
    segmented = _bounded({"challenge_id": "cid." * 10_000})
    assert len(segmented["challenge_id"]) == MAX_ARGUMENT_VALUE
    assert segmented["challenge_id"].endswith(TRUNCATED)
    assert segmented["challenge_id"].startswith("cid.cid.cid.")

    unbroken = _bounded({"challenge_id": "c" * 40_000})
    assert unbroken["challenge_id"] == "••••", "masking, not the clip, answers this one"


def test_both_services_write_the_same_marker_so_one_query_finds_both() -> None:
    """The reason the constants are identical across the two paths rather than
    tuned per path, expressed as the property it buys.

    ``services/confirm/audit.py``'s module docstring records that NO COLUMN OF
    ``audit_log`` NAMES THE SERVICE THAT WROTE THE ROW. So a reader filtering
    on the truncation marker gets both services' rows interleaved, with
    nothing on the row to tell them apart -- at which point two different
    ``limit_bytes`` values would be unattributable by construction. One bound,
    one marker key, one shape.
    """
    with redaction_budget():
        read_row = read_path_arguments({f"k{i:05d}": "v" * 100 for i in range(10_000)})
    write_row = _bounded(
        {
            "challenge_id": "chal_same",
            "confirming_device": {f"k{i:05d}": "v" * 100 for i in range(10_000)},
        }
    )

    assert ARGUMENTS_TRUNCATED_KEY in read_row
    assert ARGUMENTS_TRUNCATED_KEY in write_row
    assert set(read_row[ARGUMENTS_TRUNCATED_KEY]) == set(write_row[ARGUMENTS_TRUNCATED_KEY])
    assert (
        read_row[ARGUMENTS_TRUNCATED_KEY]["limit_bytes"]
        == write_row[ARGUMENTS_TRUNCATED_KEY]["limit_bytes"]
    )


# ---------------------------------------------------------------------------
# Against the real column.
# ---------------------------------------------------------------------------


async def test_a_refused_404_is_bounded(
    app: Starlette,
    clean: Database,
    backend: Backend,  # noqa: F811 -- the imported fixture
    key_pair: RSAKeyPair,
) -> None:
    """THE CHEAPEST ATTACK, and the one the read path has no equivalent of: no
    challenge is created, no race is won, no expiry is beaten. An
    authenticated caller aims at an id naming nothing and still writes a row.

    Measured on this exact shape before the bound: 979,108 bytes on disk,
    992,895 bytes of JSON text, in ONE row.
    """
    resp = await post(
        app,
        "chal_never_existed",
        {"signature": "sig_x", "confirming_device": ONE_MIB},
        bearer(key_pair, OWNER),
    )
    assert resp.status_code == 404

    (row,) = await rows(clean)
    assert row.arguments["challenge_id"] == "chal_never_existed", (
        "the row must still name what the probe was aimed at"
    )
    assert len(row.arguments["confirming_device"]) == MAX_ARGUMENT_VALUE
    assert row.arguments["confirming_device"].endswith(TRUNCATED)
    _assert_bounded(await _widths(clean))
    assert len(backend.calls) == 0


async def test_a_refused_409_is_bounded(
    app: Starlette,
    clean: Database,
    backend: Backend,  # noqa: F811 -- the imported fixture
    key_pair: RSAKeyPair,
) -> None:
    """The other refused transition that writes a row without reaching the
    backend. A caller who owns one already-approved challenge can replay
    against it indefinitely.

    ``verification_result`` carries the payload here and ``confirming_device``
    does not, for a reason that is a finding rather than a fixture choice: the
    409 is decided by the conditional UPDATE in
    ``services/confirm/callback.py``, which binds ``confirming_device`` as a
    parameter BEFORE Postgres evaluates the ``WHERE`` that matches no row, so
    a megabyte in that field raises ``StringDataRightTruncationError`` against
    ``challenges.confirming_device``'s ``String(128)`` and the request answers
    500 instead of 409 -- measured, 2026-09-24. That row is still written,
    still audited and now still bounded (``detail='DBAPIError'``), so the
    storage attack is closed on that path too; the 500 itself is a separate
    defect and out of this file's scope. ``challenges.verification_result`` is
    ``Text``, which is why it reaches the real 409.
    """
    await seed(clean, "chal_409_cap", status="approved")

    resp = await post(
        app,
        "chal_409_cap",
        {"signature": "sig_x", "verification_result": ONE_MIB},
        bearer(key_pair, OWNER),
    )
    assert resp.status_code == 409

    (row,) = await rows(clean)
    assert row.arguments["challenge_id"] == "chal_409_cap"
    assert len(row.arguments["verification_result"]) == MAX_ARGUMENT_VALUE
    assert row.arguments["verification_result"].endswith(TRUNCATED)
    _assert_bounded(await _widths(clean))
    assert len(backend.calls) == 0


async def test_both_rows_of_a_successful_approval_carry_the_bound(
    app: Starlette,
    clean: Database,
    backend: Backend,  # noqa: F811 -- the imported fixture
    key_pair: RSAKeyPair,
) -> None:
    """The verification that cannot be done by reading the code: the entry row
    is written from the hook ``BackendWriteClient`` invokes and the completion
    row after the request finishes, and a bound applied to one of them would
    be no bound at all.

    ``verification_result`` rather than ``confirming_device`` carries the
    payload here, because ``challenges.confirming_device`` is ``String(128)``
    and a megabyte in that field raises at the challenge UPDATE before the
    backend is ever reached -- a separate defect, out of this file's scope.
    ``challenges.verification_result`` is ``Text``, so this is the field that
    reaches a real two-row approval. Before the bound the pair wrote 1,958,212
    bytes.
    """
    await seed(clean, "chal_pair_cap")

    resp = await post(
        app,
        "chal_pair_cap",
        {"signature": "sig_x", "confirming_device": "pixel-9", "verification_result": ONE_MIB},
        bearer(key_pair, OWNER),
    )
    assert resp.status_code == 200
    assert len(backend.calls) == 1

    entry, completion = await rows(clean)
    assert [entry.outcome, completion.outcome] == ["reaching", "returned"]
    for row in (entry, completion):
        assert row.arguments["confirming_device"] == "pixel-9", "a real value was not lost"
        assert len(row.arguments["verification_result"]) == MAX_ARGUMENT_VALUE
        assert row.arguments["verification_result"].endswith(TRUNCATED)
    # The two rows carry the identical tree, which is what makes one bound at
    # the point of construction sufficient for both.
    assert entry.arguments == completion.arguments
    _assert_bounded(await _widths(clean))


async def test_an_ordinary_approval_stores_exactly_what_it_sent(
    app: Starlette,
    clean: Database,
    backend: Backend,  # noqa: F811 -- the imported fixture
    key_pair: RSAKeyPair,
) -> None:
    """The regression guard on the other side of the bound, against the real
    column rather than the helper: nothing ordinary may be altered, on either
    row, by so much as a character."""
    await seed(clean, "chal_plain_cap")

    resp = await post(
        app,
        "chal_plain_cap",
        {"signature": "sig_x", "confirming_device": "pixel-9", "verification_result": "match_ok"},
        bearer(key_pair, OWNER),
    )
    assert resp.status_code == 200

    expected = {
        "route": APPROVE_ROUTE,
        "challenge_id": "chal_plain_cap",
        "signature_present": True,
        "confirming_device": "pixel-9",
        "verification_result": "match_ok",
    }
    assert [row.arguments for row in await rows(clean)] == [expected, expected]


async def test_a_thousand_refusals_stay_bounded(
    app: Starlette,
    clean: Database,
    backend: Backend,  # noqa: F811 -- the imported fixture
    key_pair: RSAKeyPair,
) -> None:
    """The claim the bound is actually for, expressed as the number it changes
    rather than as the mechanism.

    One such refusal wrote 979,108 bytes before the bound, measured on this
    exact fixture against this exact column. This runs ten of them and
    extrapolates from what they really wrote on disk, rather than asserting
    the ratio from the constants.
    """
    for _ in range(10):
        await post(
            app,
            "chal_never_existed",
            {"signature": "sig_x", "confirming_device": ONE_MIB},
            bearer(key_pair, OWNER),
        )

    async with clean.sessionmaker() as s:
        total = await s.execute(text("SELECT SUM(pg_column_size(arguments)) FROM audit_log"))
        ten_refusals = total.scalar_one()
    assert ten_refusals is not None
    per_refusal = ten_refusals / 10
    assert per_refusal <= MAX_ARGUMENTS_BYTES, per_refusal
    # Anything within two orders of magnitude of the pre-bound cost is a
    # regression, whatever the constants happen to say.
    assert per_refusal < 979_108 / 100, per_refusal

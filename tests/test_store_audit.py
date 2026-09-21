"""Persisting through `store/audit.py`'s `append` (Task 2).

Unlike `test_store_models.py`, these start Postgres, commit, and read rows
back: `append()`'s own contract is that it commits, so its test coverage
has to go through a real database, not the model metadata alone.
"""

from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import cast

import pytest
import pytest_asyncio
from postern_core.store import audit
from postern_core.store.engine import Database
from postern_core.store.models import ABSENCE_NO_ACCESS_TOKEN, AuditEntry
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

# `audit.append` requires a correlation key and accepts no None: every row it
# writes has to be joinable to the other row of its own tool call. These probe
# rows have no partner, so the value is a fixed literal rather than a real
# `uuid4` -- what is under test here is a column round trip, not a pairing.
PROBE_CALL_ID = "probe-call-id"

# `append()` commits for real, which rules out the rollback-based `session`
# fixture the consent tests use, for two reasons rather than one. First,
# `conftest.py`'s `session` binds to a connection on which `conn.begin()`
# was already called, so SQLAlchemy resolves `join_transaction_mode` to
# `rollback_only` and `append()`'s commit never reaches that outer
# transaction at all -- the row would never actually land, so a test using
# this fixture could not demonstrate that `append()` persists anything.
# Second, reading back through that same session would return the
# identity-mapped instance, which `expire_on_commit=False` never refreshes,
# so a wrong value genuinely written to Postgres would stay invisible.
# These clear `audit_log` themselves instead, before and after, against the
# session-scoped container.


@pytest_asyncio.fixture
async def clean_audit_log(database: Database) -> AsyncIterator[None]:
    async def _clear() -> None:
        async with database.sessionmaker() as s:
            await s.execute(delete(AuditEntry))
            await s.commit()

    await _clear()
    yield
    await _clear()


async def test_append_with_redaction_budget_exhausted_true_persists_true(
    database: Database, clean_audit_log: None
) -> None:
    async with database.sessionmaker() as s:
        await audit.append(
            s,
            at=datetime.now(UTC),
            reaching_at=None,
            customer_ref=None,
            # Not a detail of these two tests, and not optional either:
            # `ck_audit_log_customer_ref_xor_absence` (models.py) rejects a
            # row that has neither a customer reference nor a reason it has
            # none, so a NULL `customer_ref` here has to name its class of
            # absence. `tests/test_audit_middleware.py` is where that column
            # is actually exercised.
            customer_ref_absence_reason=ABSENCE_NO_ACCESS_TOKEN,
            tool_name="probe",
            arguments={},
            outcome="returned",
            detail=None,
            redaction_budget_exhausted=True,
            duration_ms=0,
            request_id=None,
            refusal_reason=None,
            call_id=PROBE_CALL_ID,
            client_id=None,
            risk_signals=None,
        )
    async with database.sessionmaker() as s:
        row = (await s.execute(select(AuditEntry))).scalar_one()
    assert row.redaction_budget_exhausted is True


async def test_append_with_redaction_budget_exhausted_false_persists_false(
    database: Database, clean_audit_log: None
) -> None:
    async with database.sessionmaker() as s:
        await audit.append(
            s,
            at=datetime.now(UTC),
            reaching_at=None,
            customer_ref=None,
            # Not a detail of these two tests, and not optional either:
            # `ck_audit_log_customer_ref_xor_absence` (models.py) rejects a
            # row that has neither a customer reference nor a reason it has
            # none, so a NULL `customer_ref` here has to name its class of
            # absence. `tests/test_audit_middleware.py` is where that column
            # is actually exercised.
            customer_ref_absence_reason=ABSENCE_NO_ACCESS_TOKEN,
            tool_name="probe",
            arguments={},
            outcome="returned",
            detail=None,
            redaction_budget_exhausted=False,
            duration_ms=0,
            request_id=None,
            refusal_reason=None,
            call_id=PROBE_CALL_ID,
            client_id=None,
            risk_signals=None,
        )
    async with database.sessionmaker() as s:
        row = (await s.execute(select(AuditEntry))).scalar_one()
    assert row.redaction_budget_exhausted is False


def test_append_refuses_a_call_that_omits_the_client_id() -> None:
    """`append`'s convention, checked at runtime for the first time.

    EVERY parameter this function takes is keyword-only with no default --
    fourteen of them as of `client_id`, thirteen before it -- and each one's
    own comment in `store/audit.py` says why a default would let a caller
    record a value nobody decided on. Six came with the original schema
    (f69be5a09d99: `at`, `customer_ref`, `tool_name`, `arguments`, `outcome`,
    `detail`). Seven columns have been added since, in migration order:
    `redaction_budget_exhausted` (f45183f7ff50), `duration_ms` and
    `request_id` (561b48768c00), `refusal_reason` (0eb813c87298),
    `customer_ref_absence_reason` (3186c04c018c), `call_id` (71a4c0d9e3b2)
    and `reaching_at` (9a7d4e51c6f8). `client_id` (c91f79e6d34a) is the
    EIGHTH, and 1c64b7ed3f4b is in that chain without adding one: it widened
    two existing columns.

    WHAT ENFORCED THAT UNTIL NOW WAS MYPY ALONE, which is worth writing down
    because it is not obvious from the test suite: `make ci`'s `type` gate
    runs `mypy --strict` over `tests/` as well as over `packages` and
    `services`, so an omitted keyword is a `call-arg` error at every call
    site before it is ever a `TypeError` at runtime. This change was measured
    doing exactly that -- adding the parameter produced 14 errors across 4
    files in one `mypy` run, 13 of them `Missing named argument "client_id"
    for "append"` and the fourteenth the `_PendingEntry` construction in
    `tests/test_audit_entry_row.py`, which is how every call site was found.

    That gate is real and it is not the whole guarantee. It covers only
    callers mypy sees: this repository's own, today. A dynamic caller, a
    `**kwargs` splat that loses a key, or any caller added outside the typed
    tree gets no such error, and the cost of a silently-defaulted parameter
    is a wrong value on an append-only, regulator-facing table. This asserts
    the second line of defence directly -- that the signature itself refuses
    the call -- so a future edit that gives `client_id` a default fails here
    rather than passing everything and quietly writing NULL.

    `# type: ignore[call-arg]` is therefore the point of the test and not a
    workaround for it: the error being suppressed IS the first line of
    defence firing, and the suppression is what lets the second one be
    observed. The session is a `cast` of None because Python binds arguments
    before the body runs, so the call raises without ever touching a
    database.

    `unused-coroutine` is suppressed on the same line for the same reason and
    is a consequence of that binding order: mypy sees a coroutine function
    called and not awaited, and no coroutine object is ever created, because
    the `TypeError` fires before the body would start. Should a future edit
    give `client_id` a default, one IS created, and the test still fails --
    on `pytest.raises` not raising -- rather than passing quietly.
    """
    with pytest.raises(TypeError, match="client_id"):
        audit.append(  # type: ignore[call-arg, unused-coroutine]
            cast(AsyncSession, None),
            at=datetime.now(UTC),
            reaching_at=None,
            customer_ref=None,
            customer_ref_absence_reason=ABSENCE_NO_ACCESS_TOKEN,
            tool_name="probe",
            arguments={},
            outcome="returned",
            detail=None,
            redaction_budget_exhausted=False,
            duration_ms=0,
            request_id=None,
            refusal_reason=None,
            call_id=PROBE_CALL_ID,
        )

"""Reading consent (Task 3).

`granted_domains` filters on three independent conditions: the customer,
`granted is True`, and expiry. Each is exercised separately below so a
regression that drops one filter fails a specific test rather than a vague
one. The `session` fixture rolls back per test, so these tests never see
each other's rows regardless of execution order.
"""

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from postern_core.identity import CustomerRef
from postern_core.store import consents
from postern_core.store.models import ConsentRecord
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

CUST = CustomerRef(value="cust_7f3a")
OTHER = CustomerRef(value="cust_9b21")


async def _grant(
    session: AsyncSession,
    customer: str,
    domain: str,
    *,
    expires_at: datetime | None = None,
    granted: bool = True,
) -> None:
    session.add(
        ConsentRecord(
            customer_ref=customer,
            domain=domain,
            granted=granted,
            granted_at=datetime.now(UTC),
            expires_at=expires_at,
        )
    )
    await session.flush()


async def test_granted_domains_returns_only_this_customers_rows(session: AsyncSession) -> None:
    await _grant(session, CUST.value, "accounts")
    await _grant(session, OTHER.value, "payments")
    assert await consents.granted_domains(session, CUST) == {"accounts"}


async def test_an_ungranted_row_is_not_returned(session: AsyncSession) -> None:
    await _grant(session, CUST.value, "payments", granted=False)
    assert await consents.granted_domains(session, CUST) == set()


async def test_an_expired_row_is_treated_as_absent(session: AsyncSession) -> None:
    past = datetime.now(UTC) - timedelta(days=1)
    await _grant(session, CUST.value, "cards", expires_at=past)
    assert await consents.granted_domains(session, CUST) == set()


async def test_a_future_expiry_is_still_granted(session: AsyncSession) -> None:
    future = datetime.now(UTC) + timedelta(days=30)
    await _grant(session, CUST.value, "cards", expires_at=future)
    assert await consents.granted_domains(session, CUST) == {"cards"}


async def test_a_null_expiry_never_expires(session: AsyncSession) -> None:
    await _grant(session, CUST.value, "transactions", expires_at=None)
    assert await consents.granted_domains(session, CUST) == {"transactions"}


async def test_a_customer_with_no_rows_has_no_consent(session: AsyncSession) -> None:
    assert await consents.granted_domains(session, CUST) == set()


async def test_rollback_isolation_row_from_other_test_is_not_visible(session: AsyncSession) -> None:
    """Companion to the insert test above: proves the `session` fixture's
    rollback actually isolates tests, in either collection order. If this
    ran second and saw the `accounts` grant the first test inserted, that
    would mean the rollback did nothing.
    """
    assert await consents.granted_domains(session, CUST) == set()


# One clock: expiry is judged by the database's now() in the statement, so a
# Python process whose clock is wrong cannot change the decision.

_SKEWS = [timedelta(minutes=10), timedelta(minutes=-10)]


def _skew_python_clock(monkeypatch: pytest.MonkeyPatch, offset: timedelta) -> None:
    class _SkewedDatetime(datetime):
        @classmethod
        def now(cls, tz: Any = None) -> "_SkewedDatetime":
            real = datetime.now(tz)
            return cls.fromtimestamp((real + offset).timestamp(), tz)

    # raising=False: the module is meant to stop reading the Python clock.
    monkeypatch.setattr(consents, "datetime", _SkewedDatetime, raising=False)


@pytest.mark.parametrize("offset", _SKEWS, ids=["python-ahead", "python-behind"])
async def test_expiry_is_judged_on_the_database_clock(
    session: AsyncSession, monkeypatch: pytest.MonkeyPatch, offset: timedelta
) -> None:
    db_now = (await session.execute(select(func.now()))).scalar_one()
    await _grant(session, CUST.value, "cards", expires_at=db_now + timedelta(minutes=5))
    await _grant(session, CUST.value, "payments", expires_at=db_now - timedelta(minutes=5))
    _skew_python_clock(monkeypatch, offset)

    assert await consents.granted_domains(session, CUST) == {"cards"}

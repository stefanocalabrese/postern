"""`stub/backend.py` and `tests/fixtures/backend_responses.py` must agree.

`stub/backend.py`'s module docstring states the parity as that module's
reason to exist -- it "returns the same shapes and the same PAN/IBAN values
as `tests/fixtures/backend_responses.py`" -- and `stub/backend.py`'s `OWNERS`
repeats it as the reason ownership lives in a separate mapping instead of an
`owner` key on each row. Nothing enforced either claim: the two files
hand-duplicate three constants and four response bodies, and
`tests/test_stub_subject_scoping.py`, the only test that imports the stub,
never imports the fixtures.

The duplication is load-bearing in opposite directions. `pytest` drives the
fixtures through `httpx2.MockTransport` (`tests/test_masking_golden.py`'s
`fx` import; eight test modules in `tests/` import them, this file included);
`docker compose` drives the stub, and four `docs/verification/` records are
measurements taken against that running stack. Change one side's PAN and
those records stop corroborating anything the unit suite proves, with nothing
in the diff saying so.

This is not the §6.1 backend OpenAPI contract gate and does not stand in for
it. Both sides are local doubles written in this repo; no domain service's
published schema is involved, and none is reachable from here.
"""

from typing import Any

import pytest

from stub import backend as stub
from tests.fixtures import backend_responses as fx

# Read off the fixtures module rather than listed here, so a constant added
# there is compared without a third copy of the list to keep in step.
# Restricted to `str` and `dict` values: the fixtures file imports nothing
# today, and this keeps a later `import re` there from being demanded of the
# stub as well.
SHARED: tuple[str, ...] = tuple(
    name
    for name, value in vars(fx).items()
    if not name.startswith("_") and isinstance(value, str | dict)
)


def test_the_fixtures_publish_the_names_compared_below() -> None:
    """`SHARED` is derived, so an emptied fixtures module would leave the
    parametrized test below with zero cases, which pytest reports as a skip,
    not a failure. The names are spelled out once, here, where losing one is
    loud.

    Grew from seven to seventeen when the golden gate was widened to cover
    separator-grouped, lowercase and ordinal-split PAN/IBAN forms (audit
    finding C-07): each new shape is a constant on both sides, because a
    grouped card number reaching the compose stack must fail the same way a
    contiguous one does, and the stub is the only thing that puts one there.
    """
    assert set(SHARED) == {
        "FULL_PAN",
        "FULL_IBAN",
        "COUNTERPARTY_IBAN",
        "GROUPED_PAN",
        "HYPHEN_PAN",
        "DOTTED_PAN",
        "NBSP_PAN",
        "ORDINAL_PAN",
        "GROUPED_IBAN",
        "HYPHEN_IBAN",
        "LOWERCASE_IBAN",
        "ORDINAL_IBAN",
        "LEAKY_DESCRIPTION",
        "ACCOUNTS",
        "BALANCE",
        "TRANSACTIONS",
        "CARDS",
        "PAYEE",
    }


@pytest.mark.parametrize("name", SHARED)
def test_the_stub_repeats_each_fixture_value_exactly(name: str) -> None:
    """Equality of the whole value, not of its shape: one digit of `FULL_PAN`
    is the drift that matters, and a same-shape different-value pair is
    precisely what a structural comparison lets through.

    Parametrized so the failing test id names the constant that drifted,
    rather than one assert stopping at the first of seven.
    """
    expected: Any = getattr(fx, name)
    assert hasattr(stub, name), f"`stub/backend.py` defines no `{name}`"
    assert getattr(stub, name) == expected

import pytest
from postern_core.identity import CustomerRef, CustomerResolver

TEST_CUSTOMER = CustomerRef(value="cust_7f3a")


@pytest.fixture
def resolver() -> CustomerResolver:
    """Stands in for the access-token resolver (design decision D3)."""
    return lambda: TEST_CUSTOMER

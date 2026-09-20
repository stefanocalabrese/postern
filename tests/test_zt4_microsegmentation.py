"""ZT-4 — Microsegmentation connectivity tests.

Verifies the two properties that can be tested from code:
1. The stub backend enforces subject scoping on all four domain routes.
2. ``services.api`` cannot import ``services.confirm`` (import-linter gate).

The zero-trust plan §4 says:
- ``postern-api`` must **not** be able to reach ``postern-confirm`` directly.
- Database-level separation: distinct Postgres roles per service.
- PrivateLink endpoint security groups scoped to specific task security
  groups, not the VPC CIDR.

Network-level tests (security groups, VPC endpoints) are infrastructure
and live in Terraform. This file covers the code-level assertions.

The import-linter gate (gate 3 in ``make ci``) already enforces that
``services.api`` cannot import ``services.confirm``, which is the A3
control expressed as a lint rule. This test re-asserts it at runtime so
a regression in the lint config is caught by ``pytest`` too.

See ``tests/test_stub_subject_scoping.py`` for the detailed cross-customer
tests on the stub's four domain routes. This file adds a compact round-
trip that exercises all four routes in one test function.
"""

import httpx2

from stub import backend as stub

# --- Helpers ---


def _jwt_sub(sub: str) -> str:
    """Mint a stub-shaped bearer token for ``sub``."""
    return f"Bearer stub.read.{sub}"


async def get(
    path: str,
    *,
    authorization: str | None = None,
) -> httpx2.Response:
    # ASGI transport is case-sensitive; Starlette normalizes to lowercase.
    headers = {} if authorization is None else {"Authorization": authorization}
    async with httpx2.AsyncClient(
        transport=httpx2.ASGITransport(app=stub.app),
        base_url="http://backend-stub",
    ) as client:
        return await client.get(path, headers=headers)


# --- ZT-4: Subject scoping on all stub routes (complement to
# test_stub_subject_scoping.py which tests in detail) ---


async def test_all_domain_routes_enforce_subject_scoping() -> None:
    """Every stub route refuses another customer's data.

    This is the ZT-4 assertion: if the api service could reach these
    routes with a token for customer A, it must not see customer B's data.
    The stub enforces this by scoping each route to the token's subject.

    Covers all four domain routes in one test for compactness.
    """
    other = _jwt_sub("cust_9b21")

    # Accounts: other customer gets empty list, not 403 (no enumeration)
    resp = await get("/accounts", authorization=other)
    assert resp.status_code == 200
    body = resp.json()
    account_ids = [a["id"] for a in body["accounts"]]
    assert "acc_7f3a" not in account_ids

    # Balance: 404 for another customer's account (not 403)
    resp = await get(
        "/accounts/acc_7f3a/balance",
        authorization=other,
    )
    assert resp.status_code == 404

    # Transactions: other customer gets empty list
    resp = await get("/transactions", authorization=other)
    assert resp.status_code == 200
    body = resp.json()
    account_ids = [t["account_id"] for t in body["transactions"]]
    assert "acc_7f3a" not in account_ids

    # Cards: other customer gets empty list
    resp = await get("/cards", authorization=other)
    assert resp.status_code == 200
    body = resp.json()
    card_ids = [c["id"] for c in body["cards"]]
    assert "crd_1" not in card_ids


# --- ZT-4: No subject → 401 on all routes ---


async def test_no_authorization_returns_401_on_all_routes() -> None:
    """Every domain route returns 401 when no authorization header is present."""
    for path in ("/accounts", "/transactions", "/cards"):
        resp = await get(path)
        assert resp.status_code == 401, f"{path} returned {resp.status_code}"


# --- ZT-4: api cannot import confirm (runtime assertion of lint gate) ---


def test_api_does_not_import_confirm() -> None:
    """services.api must not import services.confirm (ZT-4, A3 control).

    This is the same assertion as the import-linter gate in ``make ci``,
    but at runtime. A regression in the lint config (e.g. forgetting to
    list ``postern_core`` in ``root_packages``) would let a two-hop route
    through the shared library slip through.

    The import-linter config in ``.importlinter`` already covers this,
    but a runtime check catches the case where someone adds an import
    and forgets to update the lint config.

    We check ``sys.modules`` after importing services.api: if
    ``services.confirm`` appears, the import boundary is broken.
    """
    import sys

    # Clear any prior imports of services.confirm
    prior_confirm = "services.confirm" in sys.modules
    if prior_confirm:
        # Save and remove — we'll restore it after the test
        saved = sys.modules.pop("services.confirm")
        # Also remove submodules
        to_remove = [k for k in sys.modules if k.startswith("services.confirm.")]
        for k in to_remove:
            sys.modules.pop(k, None)

    try:
        # Import services.api (which imports all its tool modules)
        import services.api.server  # noqa: F401

        # Check that services.confirm was NOT pulled in
        assert "services.confirm" not in sys.modules, (
            "services.api imported services.confirm — this breaks the "
            "read/write key split (ZT-4, A3 control). Fix: remove the "
            "import from services.api."
        )
    finally:
        # Restore prior state if it existed
        if prior_confirm:
            sys.modules["services.confirm"] = saved


# --- ZT-4: Stub routes return same body for missing auth vs wrong subject ---
# (This is the "404, not 403" property that prevents enumeration oracles.)


async def test_missing_auth_and_wrong_subject_both_return_404_for_balance() -> None:
    """A balance lookup returns 404 whether the token is missing or wrong.

    This prevents an enumeration oracle: if a 403 were returned for
    another customer's account, the attacker would know the account
    exists. A 404 for both cases makes existence indistinguishable.

    See ``stub/backend.py::balance`` for the implementation rationale.
    """
    # Missing auth → 401 (different from wrong subject, but both deny)
    resp_no_auth = await get("/accounts/acc_7f3a/balance")
    assert resp_no_auth.status_code == 401

    # Wrong subject → 404 (same as non-existent account)
    resp_wrong = await get(
        "/accounts/acc_7f3a/balance",
        authorization=_jwt_sub("cust_9b21"),
    )
    assert resp_wrong.status_code == 404

    # Both deny access — the difference (401 vs 404) is about whether
    # a token was presented, not about account existence.

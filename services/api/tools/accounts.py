"""`accounts.list` and `accounts.get_balance` (Task 8), as a built-in module.

A BUILT-IN, NOT A DISTRIBUTION, and the distinction is only in where the
declaration is found. This file exposes the same `postern_core.modules.read.ReadModule`
shape a third-party distribution's entry point resolves to; `services/api/tools/__init__.py`
holds it in `BUILTIN_READ_MODULES`, and `services/api/server.py` concatenates
that list with whatever `postern_core.modules.read.load_read_modules` discovers
and registers both the same way. There is one registration path, so a built-in
cannot drift into a shape a module could not express -- which is what would
quietly make the seam second-class.

The cards family went the other way, out of this package and into the
`postern_cards` distribution, so the entry-point half is exercised by shipped
code and not only by a fixture.

Neither tool takes a customer identifier: the resolver is called with no
arguments (`postern_core.identity.CustomerResolver`), so nothing the model
supplies can select whose accounts are read (handoff §6.2). `account_ref`
is typed `Ref`, never bare `str`: `Ref`'s pattern
(`^[a-z]{3}_[A-Za-z0-9]{1,32}$`) rejects a masked value outright before any
request is built, which is what stops a mask copied out of a previous tool
result being fed back in as a lookup identifier.

ZT-5: each handler records data touches on the current session's
``RiskContext`` (set by ``RiskMiddleware`` via contextvar) after the
facade call returns.
"""

from postern_core.domain.models import Account, Balance, Ref
from postern_core.facade import accounts as facade
from postern_core.modules.read import ReadContext, ReadModule, ReadTool, ToolHandler
from postern_core.risk.session import get_current_session

from services.api.tools.not_found import not_found_is_a_fixed_refusal


def _build_accounts_list(context: ReadContext) -> ToolHandler:
    async def accounts_list() -> list[Account]:
        """List the customer's accounts with their refs, labels and masked IBANs.

        Use the returned `ref` for every other account argument. Call
        `start_session` first if you have not already.
        """
        result = await facade.list_accounts(context.backend, context.resolver())
        ctx = get_current_session()
        if ctx is not None:
            ctx.record_records(len(result))
            for account in result:
                ctx.record_account(account.ref)
        return result

    return accounts_list


def _build_accounts_get_balance(context: ReadContext) -> ToolHandler:
    async def accounts_get_balance(account_ref: Ref) -> Balance:
        """Current balance for one account, with currency and an `as_of` time.

        `account_ref` comes from `accounts.list`. Report the amount and currency
        exactly as returned; do not convert or round.
        """
        async with not_found_is_a_fixed_refusal():
            result = await facade.get_balance(context.backend, context.resolver(), account_ref)
        ctx = get_current_session()
        if ctx is not None:
            ctx.record_records(1)
            ctx.record_account(account_ref)
        return result

    return accounts_get_balance


#: Both tools declare the same consent domain, and `services/api/server.py`
#: builds ONE check per domain rather than one per tool. That is load-bearing
#: rather than an optimisation: `services/api/consent.py`'s module docstring
#: measures five evaluations of the check for a single real call, all five
#: sharing one request-scoped cache entry, and counts four of them as coming
#: from the two accounts tools plus transactions and cards each evaluating
#: once. A check per tool would still cache, but the docstring's measurement
#: would stop describing the code.
MODULE = ReadModule(
    name="accounts",
    tools=(
        ReadTool(
            name="accounts.list",
            consent_domain="accounts",
            build=_build_accounts_list,
        ),
        ReadTool(
            name="accounts.get_balance",
            consent_domain="accounts",
            build=_build_accounts_get_balance,
        ),
    ),
)

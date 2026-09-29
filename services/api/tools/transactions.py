"""`transactions.list` (Task 9), as a built-in module.

A BUILT-IN, NOT A DISTRIBUTION: see `services/api/tools/accounts.py`'s module
docstring for what that means and why there is still only one registration
path.

`days` bounds the time window (schema-enforced, 1..365, default 30). The row
count is a second, independent bound: `TransactionPage.truncated` tells the
model whether `items` is the complete window or whether
`postern_core.facade.transactions.MAX_ROWS` cut it -- see that module's
docstring for why a hard cap plus a visible flag was chosen over a `limit`
argument or cursor pagination.

WHY THE SCHEMA SURVIVED THE MOVE. `days` carries an
``Annotated[int, Field(ge=1, le=MAX_DAYS)]`` bound that FastMCP reads off the
handler's signature, and the handler is still a plain async function with that
signature -- the module protocol hands the host a function, never a schema it
transcribed. `tool-surface.json` records the parameter names and which are
required, so a module that widened or dropped that bound would show the
parameter change in a diff even though the golden file does not carry the
numeric bound itself.

ZT-5: handler records data touches on the current session's ``RiskContext``
(set by ``RiskMiddleware`` via contextvar) after the facade call returns.
"""

from typing import Annotated

from postern_core.domain.models import Ref, TransactionPage
from postern_core.facade import transactions as facade
from postern_core.modules.read import ReadContext, ReadModule, ReadTool, ToolHandler
from postern_core.risk.session import get_current_session
from pydantic import Field


def _build_transactions_list(context: ReadContext) -> ToolHandler:
    async def transactions_list(
        account_ref: Ref,
        days: Annotated[int, Field(ge=1, le=facade.MAX_DAYS)] = 30,
    ) -> TransactionPage:
        """Transactions for one account, last 30 days by default.

        Widen with `days` (1 to 365) only when the customer asked for an
        older period. Counterparty account numbers are not available
        through this channel; the counterparty name is. Amounts are
        positive with a separate `direction`.

        `items` may not be the complete window: this call never returns more
        than a fixed number of rows in one response, no matter how wide
        `days` is or how many the operator's backend holds. Check `truncated`
        before reporting a total or a count to the customer -- if it is
        `true`, narrow `days` (or ask the customer to narrow the period)
        rather than presenting `items` as the whole history for the window.
        """
        result = await facade.list_transactions(
            context.backend, context.resolver(), account_ref, days
        )
        ctx = get_current_session()
        if ctx is not None:
            ctx.record_records(len(result.items))
            ctx.record_account(account_ref)
            ctx.record_days(days)
        return result

    return transactions_list


MODULE = ReadModule(
    name="transactions",
    tools=(
        ReadTool(
            name="transactions.list",
            consent_domain="transactions",
            build=_build_transactions_list,
        ),
    ),
)

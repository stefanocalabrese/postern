"""Registers `accounts.list` and `accounts.get_balance` (Task 8).

Neither tool takes a customer identifier: the resolver is called with no
arguments (`postern_core.identity.CustomerResolver`), so nothing the model
supplies can select whose accounts are read (handoff §6.2). `account_ref`
is typed `Ref`, never bare `str`: `Ref`'s pattern
(`^[a-z]{3}_[A-Za-z0-9]{1,32}$`) rejects a masked value outright before any
request is built, which is what stops a mask copied out of a previous tool
result being fed back in as a lookup identifier.
"""

from fastmcp import FastMCP
from fastmcp.server.auth import AuthCheck
from mcp.types import ToolAnnotations
from postern_core.domain.models import Account, Balance, Ref
from postern_core.facade import accounts as facade
from postern_core.facade.protocol import BackendReader
from postern_core.identity import CustomerResolver

_READ = ToolAnnotations(read_only_hint=True, open_world_hint=False)


def register(
    mcp: FastMCP, resolver: CustomerResolver, backend: BackendReader, check: AuthCheck
) -> None:
    @mcp.tool(name="accounts.list", annotations=_READ, auth=check)
    async def accounts_list() -> list[Account]:
        """List the customer's accounts with their refs, labels and masked IBANs.

        Use the returned `ref` for every other account argument. Call
        `start_session` first if you have not already.
        """
        return await facade.list_accounts(backend, resolver())

    @mcp.tool(name="accounts.get_balance", annotations=_READ, auth=check)
    async def accounts_get_balance(account_ref: Ref) -> Balance:
        """Current balance for one account, with currency and an `as_of` time.

        `account_ref` comes from `accounts.list`. Report the amount and currency
        exactly as returned; do not convert or round.
        """
        return await facade.get_balance(backend, resolver(), account_ref)

"""Registers `cards.list` (Task 10).

Takes no arguments: nothing the model supplies can select whose cards are
read (handoff §6.2), same as `accounts.list`. No row cap -- see
`packages/postern-core/src/postern_core/facade/cards.py`'s module docstring
for why this tool does not carry the `MAX_ROWS`/`truncated` treatment
`transactions.list` (Task 9) has.
"""

from fastmcp import FastMCP
from mcp.types import ToolAnnotations
from postern_core.domain.models import Card
from postern_core.facade import cards as facade
from postern_core.facade.protocol import BackendReader
from postern_core.identity import CustomerResolver

_READ = ToolAnnotations(read_only_hint=True, open_world_hint=False)


def register(mcp: FastMCP, resolver: CustomerResolver, backend: BackendReader) -> None:
    @mcp.tool(name="cards.list", annotations=_READ)
    async def cards_list() -> list[Card]:
        """List the customer's cards with their refs, labels, last-four
        digits and status.

        Card numbers are shown as the last four digits only and cannot be
        used to transact; expiry dates and security codes are never
        available here. Two cards can share the same last four digits --
        use `ref` (or `label`) to tell them apart, never `pan` alone.
        """
        return await facade.list_cards(backend, resolver())

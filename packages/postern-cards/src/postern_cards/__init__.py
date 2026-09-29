"""The cards module's READ half: `cards.list`.

THE FIRST TOOL FAMILY ON THE MODULE SEAM, and the reason it ships as its own
distribution rather than as a file under ``services/`` is the whole point of the
exercise: `services/api/server.py` names no cards module anywhere. It registers
whatever `postern_core.modules.read.load_read_modules` finds, and this
distribution's ``postern.read_modules`` entry point is how this one is found.
Deleting this distribution from an image removes `cards.list` from the tool
surface with no edit to either service.

THE WRITE HALF IS A SEPARATE DISTRIBUTION, ``postern-cards-write``, and that is
not packaging taste. ``site-packages`` is copied whole into both container
images, so a single wheel carrying both halves would put card write routing --
audience, path, method, tier -- inside the read container whatever the
Dockerfile copies. `postern_core.modules.read.refuse_distributions_declaring_both_halves`
refuses that shape outright. ``postern_cards`` therefore imports nothing from
``postern_cards_write``, and `.importlinter` has a contract saying so.

WHAT THIS MODULE DECLARES AND WHAT THE HOST DOES. This file declares a name, a
consent domain and a factory. The host does the FastMCP registration, wraps the
handler in the Postgres-backed consent check for the ``cards`` domain, installs
audit middleware around it and enumerates it in the golden masking gate. None of
that is visible here, which is the property being bought: a module author writes
a projection and a docstring, and cannot forget a control.

Takes no arguments: nothing the model supplies can select whose cards are read
(handoff §6.2), same as ``accounts.list``. No row cap -- see
`packages/postern-core/src/postern_core/facade/cards.py`'s module docstring for
why this tool does not carry the ``MAX_ROWS``/``truncated`` treatment
``transactions.list`` has.

ZT-5: the handler records data touches on the current session's
`postern_core.risk.context.RiskContext` (set by
`services/api/middleware/risk.py`'s `RiskMiddleware` via a contextvar) after the
facade call returns. A module gets the risk layer by being registered on the
host's server; recording its own row count is the one line it owes.
"""

from postern_core.domain.models import Card
from postern_core.facade import cards as facade
from postern_core.modules.read import ReadContext, ReadModule, ReadTool, ToolHandler
from postern_core.risk.session import get_current_session

__all__ = ["MODULE"]


def _build_cards_list(context: ReadContext) -> ToolHandler:
    """Bind the resolver and the backend into the handler FastMCP registers.

    The handler is a plain async function with a real signature and a real
    docstring, because that is what FastMCP reads to build the tool schema and
    the description a client shows. Nothing here touches `@mcp.tool`,
    `mcp.types.ToolAnnotations` or the ``auth=`` parameter: CLAUDE.md records
    all three as version traps, and a module that never names them survives a
    FastMCP major without an edit.
    """

    async def cards_list() -> list[Card]:
        """List the customer's cards with their refs, labels, last-four
        digits and status.

        Card numbers are shown as the last four digits only and cannot be
        used to transact; expiry dates and security codes are never
        available here. Two cards can share the same last four digits --
        use `ref` (or `label`) to tell them apart, never `pan` alone.
        """
        result = await facade.list_cards(context.backend, context.resolver())
        session = get_current_session()
        if session is not None:
            session.record_records(len(result))
        return result

    return cards_list


#: The cards module's read half, as the entry point resolves it.
MODULE = ReadModule(
    name="cards",
    tools=(
        ReadTool(
            name="cards.list",
            consent_domain="cards",
            build=_build_cards_list,
        ),
    ),
)

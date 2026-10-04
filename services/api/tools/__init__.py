"""The read tools this repository ships as built-ins, in one list.

A BUILT-IN IS A MODULE THAT DID NOT NEED A WHEEL. Each entry below is a
`postern_core.modules.read.ReadModule`, the same object a third-party
distribution's ``postern.read_modules`` entry point resolves to, and
`services/api/server.py`'s `build_server` concatenates this list with
`postern_core.modules.read.load_read_modules`' result and registers both by
one loop. There is deliberately no second registration path: a built-in
registered by hand could use a FastMCP feature the protocol cannot express, and
the seam would be second-class from the first time someone reached for one.

WHY `cards` IS NOT HERE. It moved out of this package into the `postern_cards`
distribution when the seam landed, so the entry-point half of the mechanism is
exercised by shipped code rather than only by a test fixture. Its write half
went to `postern_cards_write`, a second distribution, for the reason
`postern_core.modules.read.refuse_distributions_declaring_both_halves` gives.

WHY THE OTHER THREE STAYED. `start_session` is not a domain family at all --
it is the session bootstrap, and it is the one tool with no consent domain.
`accounts` and `transactions` are in-repo because moving them buys nothing the
cards move has not already proved and costs two distributions each. Nothing
stops them moving later: the declaration they carry is already the module one.
"""

from postern_core.modules.read import ReadModule

from services.api.tools import accounts, bootstrap, transactions

#: Registered in this order, before anything discovered. `bootstrap` first
#: because `start_session` is the tool a client is told to call first and a
#: `tools/list` in declaration order puts it where a reader looks; the rest is
#: alphabetical. `postern_core.modules.read.load_read_modules` sorts what it
#: discovers by module name, so the whole surface is ordered and
#: ``tool-surface.json`` does not churn when a distribution is reinstalled.
BUILTIN_READ_MODULES: tuple[ReadModule, ...] = (
    bootstrap.MODULE,
    accounts.MODULE,
    transactions.MODULE,
)

#: The same three, with `start_session` reporting the payments note. Chosen by
#: `services/api/server.py`'s `build_server` when the payments producer is on.
#: The declarations are equal field for field to `BUILTIN_READ_MODULES`, so
#: `tool-surface.json`'s read section cannot tell the two tuples apart.
BUILTIN_READ_MODULES_WITH_PAYMENTS: tuple[ReadModule, ...] = (
    bootstrap.PAYMENTS_MODULE,
    accounts.MODULE,
    transactions.MODULE,
)

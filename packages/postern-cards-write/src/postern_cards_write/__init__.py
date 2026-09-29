"""The cards module's WRITE half: three tier-1 card operations.

SEPARATE DISTRIBUTION, SEPARATE IMAGE, and that is the whole reason this file
is not beside `postern_cards`. The read container installs ``postern-cards``
and not ``postern-cards-write``, so it holds `cards.list` and knows nothing
about ``/cards/{card_id}/freeze``. That is the module-level expression of the
read/write key split: the read process could not mint a token ``cards.svc``
accepts for a write scope even if it knew the path, and it does not know the
path either.

NO TOOL AND NO HANDLER IS DECLARED HERE. These are routes, read by
`services/confirm/callback.py` after an operator-side approval carrying an
Ed25519 signature over the stored challenge row. Nothing in this file runs
during a request. CLAUDE.md's hard rule -- execution belongs to the approval
callback, never a tool handler -- is what makes that the shape rather than a
restriction: a module supplying write-path code would be a tool handler holding
the write key by another name.

TIER 1 FOR ALL THREE, declared and not derived. ``cards.set_label`` is a PATCH
and ``cards.freeze_card`` a POST; the verb says nothing about how hard the
customer confirms. Tier 1 is app approval -- device-bound key plus app unlock --
which satisfies SCA with two factors and triggers no Article 9 processing event,
and CLAUDE.md is explicit that tier 1 and not tier 2 is the default for writes.

NO ``cards.list`` HERE, and no read of any kind: `postern_cards_write` imports
nothing from `postern_cards`, which `.importlinter`'s
``module-halves-do-not-meet`` contract enforces in both directions.
"""

from postern_core.domain.verification import VerificationTier
from postern_core.modules.write import WriteModule, WriteOperation

__all__ = ["MODULE"]

_TIER_1 = VerificationTier.APP_APPROVAL

#: The cards module's write half, as the entry point resolves it.
#:
#: These three triples were `services/confirm/execute.py`'s `TOOL_REGISTRY`
#: entries verbatim until the seam landed; `tests/test_execute.py` still pins
#: the exact tuples the merged registry produces, which is what makes the move
#: a refactor rather than a rewrite.
MODULE = WriteModule(
    name="cards",
    operations=(
        WriteOperation(
            tool_name="cards.freeze_card",
            audience="cards.svc",
            path_template="/cards/{card_id}/freeze",
            method="POST",
            tier=_TIER_1,
        ),
        WriteOperation(
            tool_name="cards.unfreeze_card",
            audience="cards.svc",
            path_template="/cards/{card_id}/unfreeze",
            method="POST",
            tier=_TIER_1,
        ),
        WriteOperation(
            tool_name="cards.set_label",
            audience="cards.svc",
            path_template="/cards/{card_id}/label",
            method="PATCH",
            tier=_TIER_1,
        ),
    ),
)

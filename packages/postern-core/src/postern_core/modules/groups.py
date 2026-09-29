"""The two entry-point group names, and nothing else.

A THIRD MODULE FOR TWO STRINGS, and the reason is `.importlinter`'s
``api-not-module-write-half`` contract. `postern_core.modules.read` has to know
the WRITE group's name, because
`postern_core.modules.read.refuse_distributions_declaring_both_halves` compares
the two groups' distributions and that check belongs on the read path -- it is
the read process that must refuse a wheel carrying both halves. Importing the
name from `postern_core.modules.write` would put the write half's module in the
read path's import graph and break the contract for every deployment at once.

So the names live where both halves can reach them and neither half's types
do. Nothing is imported here on purpose: this module must stay safe for the
read path to import.
"""

#: Where a module declares its read half. The value resolves to a
#: `postern_core.modules.read.ReadModule`.
READ_GROUP = "postern.read_modules"

#: Where a module declares its write half. The value resolves to a
#: `postern_core.modules.write.WriteModule`.
WRITE_GROUP = "postern.write_modules"

"""The customer_ref width defect: validation and storage agreed by accident.

`identity.py`'s `_OPAQUE` and `models.py`'s two `customer_ref` columns each
encode a maximum length independently, with nothing that ties them
together. `_OPAQUE` admits `cust` (4) + one separator (1) + up to 60
alphanumerics = 65 characters, which is one character past the 64-wide
columns `consents.customer_ref` and `audit_log.customer_ref` used to
declare -- a value `CustomerRef` accepted could not be inserted. The
columns are now `String(128)`, deliberately wider than 65, so the next
`_OPAQUE` widening does not silently reopen this gap.

This test does not hardcode 65: it derives the longest string `_OPAQUE`
accepts by parsing the pattern itself, so it keeps tracking `_OPAQUE` if
that pattern changes, and checks the result against both columns' declared
widths read from the SQLAlchemy model rather than against another literal.
"""

from __future__ import annotations

# `re._parser` is CPython's own regex parser (renamed from the public
# `sre_parse` module in 3.11, which this project's pinned 3.12 post-dates).
# It has no typeshed stubs, so mypy treats everything read from it as `Any`
# from this import on. Using the interpreter's actual parser is more
# robust than a hand-rolled regex-on-the-regex scan: it is the exact code
# `re.compile` runs on `_OPAQUE`, not an approximation of it.
import re._parser as _sre_parse  # type: ignore[import-not-found]
from typing import Any

from postern_core.identity import _OPAQUE, CustomerRef
from postern_core.store.models import AuditEntry, ConsentRecord
from sqlalchemy import String


def _longest_char_in_class(items: Any) -> str:
    """One character an `IN` (character class) node can match.

    Any member does: for a length calculation every member of a class is
    exactly one character, so the first one found is as good as any other.
    Raises on a negated class (`[^...]`), which has no finite, enumerable
    membership to pick from -- `_OPAQUE` has no such class today.
    """
    if items and items[0][0] is _sre_parse.NEGATE:
        raise ValueError(f"negated character class has no single representative member: {items!r}")
    for op, av in items:
        if op is _sre_parse.LITERAL:
            return chr(av)
        if op is _sre_parse.RANGE:
            return chr(av[0])
    raise ValueError(f"empty or unsupported character class: {items!r}")


def _longest_match(nodes: Any) -> str:
    """The longest string this parsed regex node sequence can match.

    Walks the node types `_OPAQUE` actually compiles to -- `AT` (an
    anchor, zero-width), `LITERAL`, `IN`, and `MAX_REPEAT` -- rather than
    assuming any particular pattern text, so this keeps tracking `_OPAQUE`
    if its literal prefix or its bound changes. Raises on a construct with
    no finite longest match (an unbounded repeat, or anything else this
    function does not recognize) instead of guessing: `_OPAQUE` has none
    of those today, and a pattern that grows one should fail this test
    loudly rather than silently under- or over-count.
    """
    out: list[str] = []
    for op, av in nodes:
        if op is _sre_parse.AT:
            continue
        elif op is _sre_parse.LITERAL:
            out.append(chr(av))
        elif op is _sre_parse.IN:
            out.append(_longest_char_in_class(av))
        elif op is _sre_parse.MAX_REPEAT:
            lo, hi, sub = av
            if hi is _sre_parse.MAXREPEAT:
                raise ValueError(f"unbounded repeat, no finite longest match: {av!r}")
            out.append(_longest_match(sub) * hi)
        else:
            raise ValueError(f"unsupported regex construct for length derivation: {op!r}")
    return "".join(out)


def _longest_legal_customer_ref() -> str:
    """The longest value `identity._OPAQUE` accepts, derived from the pattern."""
    return _longest_match(_sre_parse.parse(_OPAQUE))


def test_the_derivation_actually_produces_sixty_five_characters_today() -> None:
    """Pins the derivation itself against today's known-correct answer.

    Not a hardcoded expectation on `CustomerRef` or the columns -- those
    are checked against the derived value below, not against `65` -- this
    only confirms the parser walk above is computing what §identity.py's
    comment claims (`cust` + one separator + 60 alphanumerics), so a bug in
    the derivation itself doesn't silently pass by agreeing with whatever
    it happens to compute.
    """
    assert len(_longest_legal_customer_ref()) == 65


def test_longest_legal_customer_ref_is_accepted_by_customer_ref() -> None:
    CustomerRef(value=_longest_legal_customer_ref())


def test_longest_legal_customer_ref_fits_the_consents_column() -> None:
    # `TypeEngine`, `.type`'s declared type, has no `.length`; only its
    # `String` subtype does. The `isinstance` check narrows for mypy and
    # doubles as a check that the column is still a `String` column at all.
    column_type = ConsentRecord.__table__.c.customer_ref.type
    assert isinstance(column_type, String)
    assert column_type.length is not None
    assert len(_longest_legal_customer_ref()) <= column_type.length


def test_longest_legal_customer_ref_fits_the_audit_log_column() -> None:
    column_type = AuditEntry.__table__.c.customer_ref.type
    assert isinstance(column_type, String)
    assert column_type.length is not None
    assert len(_longest_legal_customer_ref()) <= column_type.length

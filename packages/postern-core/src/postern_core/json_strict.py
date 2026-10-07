"""``json.loads`` that refuses the numbers RFC 8259 has no spelling for.

Python's ``json`` accepts three constants the standard does not, ``NaN``,
``Infinity`` and ``-Infinity``, and it decodes a literal too large for a double,
``1e999``, to ``inf`` WITHOUT calling ``parse_constant``. Measured on CPython
3.12: ``json.loads("1e999")`` is ``inf``, so a parser that hooks only
``parse_constant`` hands the same infinity to a handler through the other door.

Why it matters here: a non-finite float in a field that is audited makes
PostgreSQL refuse the JSONB token, so the audit write fails and a request,
including a cross-customer probe, can end with no row. Refusing at parse time
makes it an ordinary malformed body, answered before any handler runs.

``NonFiniteJsonError`` is a ``ValueError`` on purpose: every caller already has
a branch for a body that is not JSON (``except ValueError``), and this lands in
it unchanged. It is not a ``json.JSONDecodeError``, so a caller that catches
only that class has to be widened, which is what the three device-grant
handlers were.

Duplicate keys, nesting depth and size are NOT handled here. Depth raises
``RecursionError`` exactly as ``json.loads`` does; it is a ``RuntimeError``, not
a ``ValueError``, so a caller must catch it by name, and every call site in
``services/`` does; size is the body-limit middlewares' job.
"""

from __future__ import annotations

import json
import math
from typing import Any, NoReturn


class NonFiniteJsonError(ValueError):
    """The document carries ``NaN``, ``Infinity``, ``-Infinity`` or an overflowing number."""


def _refuse_constant(name: str) -> NoReturn:
    raise NonFiniteJsonError(f"non-finite JSON number {name}")


def _finite_float(literal: str) -> float:
    value = float(literal)
    if not math.isfinite(value):
        raise NonFiniteJsonError(f"JSON number {literal[:32]!r} does not fit a finite double")
    return value


def loads_finite(data: bytes | str) -> Any:
    """Parse ``data`` as JSON, refusing any non-finite number with ``NonFiniteJsonError``.

    Everything else is ``json.loads``: invalid JSON raises ``json.JSONDecodeError``,
    bytes that are not UTF-8 raise ``UnicodeDecodeError``, and nesting past the
    interpreter's limit raises ``RecursionError``.
    """
    return json.loads(data, parse_constant=_refuse_constant, parse_float=_finite_float)

"""``postern_core.json_strict.loads_finite``: ``json.loads`` that refuses non-finite numbers.

Python's ``json`` accepts ``NaN``, ``Infinity`` and ``-Infinity``, which RFC 8259
does not, and it decodes a literal like ``1e999`` to ``inf`` without calling
``parse_constant`` at all. Both ends are covered here, because a parser that
refuses only the constants still hands a handler an infinity.
"""

from __future__ import annotations

import json
import math
from typing import Any

import pytest
from postern_core.json_strict import NonFiniteJsonError, loads_finite

NON_FINITE_LITERALS = ["NaN", "Infinity", "-Infinity", "1e999", "-1e999", "1E999", "1.5e400"]


def test_the_stdlib_accepts_what_this_parser_refuses() -> None:
    """The gap, measured: without this the other tests prove nothing."""
    assert math.isnan(json.loads("NaN"))
    assert json.loads("Infinity") == math.inf
    assert json.loads("-Infinity") == -math.inf
    assert json.loads("1e999") == math.inf
    assert json.loads("-1e999") == -math.inf


@pytest.mark.parametrize("literal", NON_FINITE_LITERALS)
@pytest.mark.parametrize(
    "template",
    [
        "{}",
        '{{"a": {}}}',
        '{{"a": {{"b": [1, {}]}}}}',
        "[{}]",
        "[[{}], 2]",
        '[{{"k": {}}}]',
    ],
    ids=["top-level", "dict value", "deep dict", "in array", "nested array", "array of dicts"],
)
def test_a_non_finite_number_is_refused_wherever_it_sits(literal: str, template: str) -> None:
    text = template.format(literal)
    with pytest.raises(NonFiniteJsonError):
        loads_finite(text)
    with pytest.raises(NonFiniteJsonError):
        loads_finite(text.encode())


def test_the_refusal_is_a_value_error_so_existing_malformed_branches_catch_it() -> None:
    assert issubclass(NonFiniteJsonError, ValueError)
    with pytest.raises(ValueError):
        loads_finite("NaN")


def test_the_refusal_is_not_a_decode_error() -> None:
    """It says what it is; a caller catching only ``JSONDecodeError`` must be changed."""
    assert not issubclass(NonFiniteJsonError, json.JSONDecodeError)


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("0", 0),
        ("-0.0", -0.0),
        ("1e308", 1e308),
        ("-1e308", -1e308),
        ("5e-324", 5e-324),
        ("1e-999", 0.0),
        ("123456789012345678901234567890", 123456789012345678901234567890),
        ("1.5", 1.5),
        ('{"a": [1, 2.5, "NaN"]}', {"a": [1, 2.5, "NaN"]}),
        ('"Infinity"', "Infinity"),
        ("null", None),
        ("true", True),
    ],
)
def test_finite_json_parses_as_json_loads_does(text: str, expected: Any) -> None:
    assert loads_finite(text) == expected
    assert loads_finite(text.encode()) == expected
    assert loads_finite(text) == json.loads(text)


def test_a_negative_zero_keeps_its_sign() -> None:
    assert math.copysign(1.0, loads_finite("-0.0")) == -1.0


@pytest.mark.parametrize("text", ["{not json", "", "[1,", "nul", "{'a': 1}"])
def test_invalid_json_still_raises_a_decode_error(text: str) -> None:
    with pytest.raises(json.JSONDecodeError):
        loads_finite(text)
    with pytest.raises(json.JSONDecodeError):
        loads_finite(text.encode())


def test_bytes_that_are_not_utf8_still_raise_a_value_error() -> None:
    with pytest.raises(UnicodeDecodeError):
        loads_finite(b"\xff\xfe\x00")


def test_nesting_past_the_recursion_limit_still_raises_recursion_error() -> None:
    """Unchanged from ``json.loads``; callers that name it keep naming it."""
    with pytest.raises(RecursionError):
        loads_finite("[" * 200_000)

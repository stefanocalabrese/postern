"""The one normal form a resource indicator is compared in.

`postern_core.auth.resource_uri` is pure, so every case the session-token
spec names for ``resource`` (host case, ``:443``, an empty path, a significant
trailing slash, a fragment, a relative reference) is checked here without an
app, and both services' refusals lean on the same two functions.
"""

from __future__ import annotations

import pytest
from postern_core.auth.resource_uri import is_normal_https_resource, normalize_resource

NORMALIZED = [
    ("https://mcp.example/mcp", "https://mcp.example/mcp"),
    ("HTTPS://MCP.Example/mcp", "https://mcp.example/mcp"),
    ("https://mcp.example:443/mcp", "https://mcp.example/mcp"),
    ("https://mcp.example:/mcp", "https://mcp.example/mcp"),
    ("https://mcp.example:8443/mcp", "https://mcp.example:8443/mcp"),
    ("http://mcp.example:80/mcp", "http://mcp.example/mcp"),
    ("https://mcp.example", "https://mcp.example/"),
    ("https://mcp.example/MCP", "https://mcp.example/MCP"),
    ("https://mcp.example/mcp/", "https://mcp.example/mcp/"),
    ("https://mcp.example/a%2Fb", "https://mcp.example/a%2Fb"),
    ("https://mcp.example/a%2fb", "https://mcp.example/a%2fb"),
    ("https://[2001:DB8::1]:443/mcp", "https://[2001:db8::1]/mcp"),
    ("https://mcp.example/mcp?x=1", "https://mcp.example/mcp?x=1"),
]


@pytest.mark.parametrize(("value", "expected"), NORMALIZED)
def test_the_normal_form(value: str, expected: str) -> None:
    assert normalize_resource(value) == expected


def test_a_trailing_slash_names_a_different_resource() -> None:
    assert normalize_resource("https://mcp.example/mcp") != normalize_resource(
        "https://mcp.example/mcp/"
    )


@pytest.mark.parametrize(
    "value",
    [
        "",
        "https://mcp.example/mcp#frag",
        "https://mcp.example/mcp#",
        "/mcp",
        "mcp.example/mcp",
        "urn:postern:mcp",
        "https://",
        "https://mcp.example:notaport/mcp",
        "https://mcp.example:99999/mcp",
    ],
)
def test_a_value_that_cannot_name_a_resource_is_none(value: str) -> None:
    assert normalize_resource(value) is None


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("https://mcp.postern.internal/mcp", True),
        ("https://mcp.example/", True),
        ("https://mcp.example", False),
        ("HTTPS://mcp.example/mcp", False),
        ("https://MCP.example/mcp", False),
        ("https://mcp.example:443/mcp", False),
        ("http://mcp.example/mcp", False),
        ("https://mcp.example/mcp#x", False),
        ("postern", False),
    ],
)
def test_is_normal_https_resource(value: str, expected: bool) -> None:
    assert is_normal_https_resource(value) is expected


# One resource has exactly one normal form, and two resources never share one.
# Each probe below either merged with a different value or kept a part RFC 9110
# forbids, before 1 October 2026.

COLLISION_PAIRS = [
    # U+212A KELVIN SIGN lower-cases to ASCII "k" under str.lower().
    ("https://mcp.Key.example/mcp", "https://mcp.key.example/mcp"),
    # urlsplit strips tab, CR and LF anywhere and whitespace at the start.
    ("https://mcp.exa\tmple/mcp", "https://mcp.example/mcp"),
    ("https://mcp.example/m\ncp", "https://mcp.example/mcp"),
    ("https://mcp.example/m\rcp", "https://mcp.example/mcp"),
    (" https://mcp.example/mcp", "https://mcp.example/mcp"),
    # An IPvFuture literal lost its brackets.
    ("https://[v1.mcp.example]/mcp", "https://v1.mcp.example/mcp"),
]


@pytest.mark.parametrize(("value", "other"), COLLISION_PAIRS)
def test_two_different_values_never_share_a_normal_form(value: str, other: str) -> None:
    normal = normalize_resource(value)
    assert normal is None or normal != normalize_resource(other)


@pytest.mark.parametrize(
    "value",
    [
        "https://mcp.Key.example/mcp",
        "https://mcp.éxample/mcp",
        "https://mcp.example/café",
        "https://[v1.mcp.example]/mcp",
        "https://mcp.example:0/mcp",
        "https://mcp;x.example/mcp",
        "https://mcp%2eexample/mcp",
        "https://mcp.example/mcp%00",
        "https://mcp.example\\mcp",
        "https://mcp.example/m cp",
        "https://mcp.example/mcp ",
        " https://mcp.example/mcp",
    ],
)
def test_a_non_ascii_or_ambiguous_value_is_none(value: str) -> None:
    assert normalize_resource(value) is None
    assert is_normal_https_resource(value) is False


@pytest.mark.parametrize("char", [chr(c) for c in range(0x20)] + ["\x7f"])
@pytest.mark.parametrize(
    "template",
    ["https://mcp.exa{c}mple/mcp", "https://mcp.example/m{c}cp", "{c}https://mcp.example/mcp"],
)
def test_every_control_character_is_none(char: str, template: str) -> None:
    value = template.format(c=char)
    assert normalize_resource(value) is None
    assert is_normal_https_resource(value) is False


@pytest.mark.parametrize(
    "value",
    [
        "https://user:pw@mcp.example/mcp",
        "https://user@mcp.example/mcp",
        "https://@mcp.example/mcp",
        "https://mcp.example@evil.example/mcp",
    ],
)
def test_userinfo_is_none(value: str) -> None:
    """RFC 9110 section 4.2.4: a sender MUST NOT generate userinfo in an https URI."""
    assert normalize_resource(value) is None
    assert is_normal_https_resource(value) is False


@pytest.mark.parametrize(
    ("value", "other"),
    [
        ("https://[2001:db8:0::1]/mcp", "https://[2001:db8::1]/mcp"),
        ("https://mcp.example./mcp", "https://mcp.example/mcp"),
    ],
)
def test_ipv6_and_trailing_dot_spellings_are_not_canonicalised(value: str, other: str) -> None:
    """Two spellings of one host compare unequal: closed, never merged."""
    assert normalize_resource(value) is not None
    assert normalize_resource(value) != normalize_resource(other)

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

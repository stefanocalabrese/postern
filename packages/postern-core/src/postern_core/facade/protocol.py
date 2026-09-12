"""The structural contract `build_server` requires of a backend (Task 4).

Task 4 assembles the MCP server before any tool calls the backend, so
`services.api.server.build_server` has no business depending on
`postern_core.facade.client.BackendClient` (Task 6, concrete, httpx2-based):
that module does not exist yet, and even once it does, `build_server` only
ever passes the backend through to tools, it never calls it itself.

This mirrors the seam `postern_core.identity.CustomerResolver` already uses
for the customer resolver: a minimal `Protocol` describing only what is
actually called, so the concrete implementation can be swapped, tested, or
simply not exist yet without breaking the type check.

Kept to exactly the one read method later tasks use. Task 6's `BackendClient`
must satisfy this Protocol structurally; it does not import it.
"""

from collections.abc import Mapping
from typing import Any, Protocol

from postern_core.identity import CustomerRef


class BackendReader(Protocol):
    """The one read operation a tool handler needs from the backend façade."""

    async def get_json(
        self,
        path: str,
        *,
        customer: CustomerRef,
        audience: str = "accounts.svc",
        params: Mapping[str, Any] | None = None,
    ) -> Any: ...

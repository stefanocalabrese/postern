"""One fixed refusal for a backend 404 or 403, and nothing else the backend says.

`services/api` builds FastMCP with `mask_error_details=True`, so a
`BackendError` escaping a tool handler reaches the model as ``Error calling
tool 'x'``. For a tool that takes a caller-chosen account ref that is too
little: the model cannot tell "that account does not exist" from "the backend
is down", and retries or reports an outage for a typo. A 404 and a 403 are the
statuses that say the model's own input is wrong, so both are mapped to a fixed
`ToolError`. Every other status (400, 401, 500, 503) and a failure to reach the
backend stay masked as ``Error calling tool 'x'``, except that FastMCP itself
words a raw timeout and an HTTP 429 as fixed sentences of its own (nothing from
the backend's body in either).

THE TEXT IS ONE CONSTANT FOR EVERY REF, AND 403 IS MAPPED WITH 404. The backend
is required to answer 404 for an account that exists and belongs to another
customer exactly as for one that does not (`dev-docs/postern-zero-trust-plan.md`
section 3.2, `stub/backend.py`, operator item 1 in CLAUDE.md). A backend that
answers 403 for the foreign ref would otherwise make the two read differently
here (`not found` against `Error calling tool 'x'`), an existence oracle (A5),
so a foreign ref and an unknown ref are indistinguishable whatever the backend
answers. `tests/test_not_found_mapping.py` asserts byte-identical replies
against the real stub and against a backend that answers 403.
`from None` drops the `BackendError`, whose text is the scrubbed backend body.

`payments.py` keeps its own sentences (``account not found``, ``payee not
found``) for the same mapping on its own refs.
"""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastmcp.exceptions import ToolError
from postern_core.facade.client import BackendError

NOT_FOUND = "not found"
_NOT_FOUND_STATUSES = frozenset({403, 404})


@asynccontextmanager
async def not_found_is_a_fixed_refusal() -> AsyncIterator[None]:
    """Run the body; a `BackendError` with status 404 or 403 becomes ``ToolError(NOT_FOUND)``."""
    try:
        yield
    except BackendError as exc:
        if exc.status in _NOT_FOUND_STATUSES:
            raise ToolError(NOT_FOUND) from None
        raise

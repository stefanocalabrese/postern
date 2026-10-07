"""One fixed refusal for a backend 404, and nothing else the backend says.

`services/api` builds FastMCP with `mask_error_details=True`, so a
`BackendError` escaping a tool handler reaches the model as ``Error calling
tool 'x'``. For a tool that takes a caller-chosen account ref that is too
little: the model cannot tell "that account does not exist" from "the backend
is down", and retries or reports an outage for a typo. A 404 is the one status
that is the model's own input being wrong, so it is mapped to a fixed
`ToolError` and every other status (500, 503, a transport failure) stays
masked.

THE TEXT IS ONE CONSTANT FOR EVERY REF. The backend answers 404 for an account
that exists and belongs to another customer exactly as for one that does not
(handoff section 6.2; `tests/test_stub_subject_scoping.py`), so the reply
confirms nothing about which it was, and
`tests/test_not_found_mapping.py` asserts the two replies are byte-identical.
`from None` drops the `BackendError`, whose text is the scrubbed backend body.

`payments.py` keeps its own sentences (``account not found``, ``payee not
found``) for the same mapping on its own refs.
"""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastmcp.exceptions import ToolError
from postern_core.facade.client import BackendError

NOT_FOUND = "not found"


@asynccontextmanager
async def not_found_is_a_fixed_refusal() -> AsyncIterator[None]:
    """Run the body; a `BackendError` with status 404 becomes ``ToolError(NOT_FOUND)``."""
    try:
        yield
    except BackendError as exc:
        if exc.status == 404:
            raise ToolError(NOT_FOUND) from None
        raise

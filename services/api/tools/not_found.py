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
found``) and maps the same `NOT_FOUND_STATUSES` (403 and 404) on its own refs.

A 403 LEAVES ONE LOG LINE, A 404 NONE. Mapping 403 to `not found` hides a
misconfigured minter (wrong audience or scope: the backend rejects every token
this service sends) behind what reads as customers mistyping refs: the audit
row of a 403 (`reaching`, then `raised` / ``ToolError``) is a 404's, and
FastMCP's own line (`Error calling tool 'x'`) names no status. So a 403, and
only a 403, logs a fixed warning on this module's logger, grep for ``backend
answered 403 on a caller-chosen ref``. The audit schema is not changed: the
log line is the signal. The line carries no ref, no tool argument and no body,
and is limited to one per `_WARN_INTERVAL_SECONDS` per process so a caller who
probes refs cannot flood the log. A 403 on EVERY call means the api's token is
rejected.
"""

import logging
import time
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager

from fastmcp.exceptions import ToolError
from postern_core.facade.client import BackendError

logger = logging.getLogger(__name__)

NOT_FOUND = "not found"
#: Public: `tools/payments.py` maps the same two statuses to its own sentences.
NOT_FOUND_STATUSES = frozenset({403, 404})

#: At most one 403 warning per this many seconds per process.
_WARN_INTERVAL_SECONDS = 60.0
#: Injectable for tests; monotonic, so a wall-clock step cannot reopen the window.
_clock: Callable[[], float] = time.monotonic
#: When the last 403 warning was written; None until the first.
_last_warned_at: float | None = None

_FORBIDDEN_WARNING = (
    "backend answered 403 on a caller-chosen ref; reported to the model as not found. "
    "A 403 on every call means the api's token is rejected: check the minter's "
    "audience and scope."
)


def _warn_forbidden() -> None:
    """Write the 403 warning unless one was written within the window."""
    global _last_warned_at
    now = _clock()
    if _last_warned_at is not None and now - _last_warned_at < _WARN_INTERVAL_SECONDS:
        return
    _last_warned_at = now
    logger.warning(_FORBIDDEN_WARNING)


@asynccontextmanager
async def not_found_is_a_fixed_refusal() -> AsyncIterator[None]:
    """Run the body; a `BackendError` with status 404 or 403 becomes ``ToolError(NOT_FOUND)``."""
    try:
        yield
    except BackendError as exc:
        if exc.status in NOT_FOUND_STATUSES:
            if exc.status == 403:
                _warn_forbidden()
            raise ToolError(NOT_FOUND) from None
        raise

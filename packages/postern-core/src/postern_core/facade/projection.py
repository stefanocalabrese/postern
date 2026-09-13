"""Safe construction of an MCP-facing domain model from backend data.

This closes the same channel for the third time in this codebase. Task 2
documented it as a caller obligation in `postern_core.domain.masking`'s
module docstring and CLAUDE.md's hard rule of the same shape: a
`pydantic.ValidationError`'s structured `.errors()` output (and `.json()`)
carries the raw offending value regardless of `hide_input_in_errors`, which
covers only `str()`/`repr()` of the exception. Task 4 closed it for
`token_customer_resolver` by catching the token issuer's own
`ValidationError` and re-raising a plain `PermissionError`. It reappeared on
the return-value side in Task 8's `facade/accounts.py`: a backend-supplied
IBAN or PAN that fails `MaskedIban`/`MaskedPan`'s own validator (missing
field, `null`, or a value that is IBAN/PAN-shaped but fails the mod-97/digit
check) raises `pydantic.ValidationError` while building `Account`/`Balance`.

Left uncaught, that `ValidationError` propagates out of the tool handler to
FastMCP's own dispatcher (`fastmcp/server/server.py`, `call_tool`'s `except
PydanticValidationError as e:` branch, verified by reading that source),
which logs it via `logger.warning(..., e.errors(include_url=False))` --
`.errors()`, not `.str()`, so `hide_input_in_errors` does not apply, and the
raw value reaches the server's own logs. In a bank those logs typically ship
to a SIEM, often a third party: a real egress channel for exactly the values
this system exists to keep in, distinct from (and in addition to) the
model-facing channel the golden masking harness scans.

`build_model` is the one place every façade projection module (accounts,
transactions, cards, the session bootstrap) should construct a domain model
from backend-derived fields, so this channel is closed once here rather than
once per domain.
"""

from collections.abc import Callable

from pydantic import ValidationError

from postern_core.facade.client import BackendError


def build_model[Model](factory: Callable[[], Model], *, resource: str) -> Model:
    """Call `factory` and turn any `pydantic.ValidationError` it raises into
    a `BackendError` naming only the failing field(s), never the value.

    `factory` is typically `lambda: SomeModel(**fields_read_from_the_backend_payload)`.

    Only `error["loc"]` (the field path, defined by this codebase's own
    model, never backend data) is read from `exc.errors(include_input=False)`;
    `include_input=False` is redundant defence in depth given that, kept
    because it costs nothing and documents the intent at the call site.

    `raise ... from None`, not `from exc`: measured, not assumed, to be
    defence in depth rather than the load-bearing fix for this codebase's
    models today. The actual leak this function closes is FastMCP's own
    `except PydanticValidationError as e:` branch logging
    `e.errors(include_url=False)` -- structured output, ignores
    `hide_input_in_errors` -- which `build_model` prevents by never letting
    a bare `ValidationError` reach that dispatcher at all. Separately,
    `logger.exception(...)` on the generic-exception path renders a chained
    exception's summary via `str()`, and `_Strict.model_config
    ["hide_input_in_errors"]` (set on every current MCP-facing model) already
    makes `str(ValidationError)` omit the value; confirmed by removing `from
    None` and rerunning `tests/test_tools_accounts.py::
    test_accounts_list_validation_error_does_not_leak_the_raw_iban` -- it
    still passed. `from None` stays anyway: a plain `pydantic.BaseModel`
    without `hide_input_in_errors` set DOES put the raw value in `str()`
    (confirmed separately), so relying on every present and future model
    along this path setting that config correctly is a materially weaker
    guarantee than an exception chain that never reaches the `ValidationError`
    in the first place. Verified with a `caplog`-driven test at DEBUG on the
    `fastmcp` logger specifically (`fastmcp.propagate = False`, set by
    `fastmcp.utilities.logging.configure_logging`, so a plain root-logger
    capture misses it) in `tests/test_tools_accounts.py`.
    """
    try:
        return factory()
    except ValidationError as exc:
        fields = ", ".join(str(error["loc"][-1]) for error in exc.errors(include_input=False))
        raise BackendError(
            502,
            f"backend response for {resource!r} failed validation on field(s): {fields}",
            "The bank returned data in an unexpected shape. Tell the customer and retry later.",
        ) from None

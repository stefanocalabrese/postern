"""Read-path backend façade (handoff §8.6).

This client exposes GET only. The write path lives in services/confirm and is
reachable only from a signed approval, so a write method here would be the
capability the whole design removes.

`httpx2` is FastMCP 4's HTTP dependency; see dev-docs/decisions/0001.

Must satisfy `postern_core.facade.protocol.BackendReader` structurally
(Task 4); this module deliberately does not import that Protocol, so
`mypy --strict` on `services/api/server.py` is what catches drift between the
two, per the plan.
"""

import warnings
from collections.abc import Awaitable, Mapping
from typing import Any, Protocol
from urllib.parse import urlsplit

import httpx2
from pydantic import TypeAdapter

from postern_core.domain.masking import FreeText
from postern_core.identity import CustomerRef

# Built once at import time: validating a bare string against `FreeText`
# doesn't need a wrapping `BaseModel`, just its `AfterValidator`.
_FREE_TEXT: TypeAdapter[str] = TypeAdapter(FreeText)


def _scrub(text: str) -> str:
    return _FREE_TEXT.validate_python(text)


class BackendError(RuntimeError):
    """A backend call failed. `guidance` is what the agent should be told to do.

    `detail` is always the *scrubbed* backend text (see `_detail` below): a
    `BackendError` raised inside a tool handler propagates to FastMCP and
    from there into the model's context, which lands in a vendor chat history
    that cannot be recalled. An operator backend's 4xx/5xx body can carry a
    PAN, an IBAN, an account number or a customer name; nothing derived from
    it may reach this exception unscrubbed.
    """

    def __init__(self, status: int, detail: str, guidance: str) -> None:
        super().__init__(f"{status}: {detail}")
        self.status = status
        self.detail = detail
        self.guidance = guidance


class TokenMinter(Protocol):
    """Mints the internal token for one backend hop (handoff §7.2)."""

    def __call__(self, customer: CustomerRef, audience: str) -> str: ...


class BackendRequestHook(Protocol):
    """Run, and awaited, immediately before this client reaches the backend.

    Takes nothing and returns nothing, and that shape is the coupling budget
    rather than an accident. `services/api`'s audit log needs a durable row
    committed before any customer data is touched, and that row carries a
    tool name and a scrubbed argument dict -- MCP vocabulary this package
    does not have and must not learn. So the caller PRE-BINDS those values
    into a zero-argument callable and this client only decides WHEN to run
    it. The same pattern `TokenMinter` above and
    `postern_core.facade.protocol.BackendReader` already use: a Protocol
    narrow enough that the implementation can live anywhere, which is why
    `postern_core.facade` still imports nothing from `postern_core.store`.

    IF IT RAISES, THE REQUEST IS NOT MADE. That is the contract, not a side
    effect of where it is called: the whole value of running first is that a
    caller which cannot record the touch can stop it. `get_json` does not
    catch it, so the exception reaches the tool handler as the call's own
    failure.

    Idempotency is the CALLER's problem, not this client's. One tool call may
    reach `get_json` more than once -- no facade function does today, each
    making exactly one request, but a read-before-write would -- and this
    client invokes the hook once per request, every time, with no memory
    between them.
    """

    def __call__(self) -> Awaitable[None]: ...


class StubTokenMinter:
    """Placeholder until Plan 3 wires the Vault-backed `InternalTokenMinter`.

    Never deploy this: it mints a fake bearer token no real backend accepts.
    Nothing in this codebase can turn that into a hard failure without a
    deployment decision Task 12 owns (an environment flag, a settings check),
    so the cheap guard available here is to make every call loud: a
    `RuntimeWarning` on each use, so a deployment that never wired the real
    minter shows it in logs/warning capture rather than staying silent.
    """

    def __call__(self, customer: CustomerRef, audience: str) -> str:
        warnings.warn(
            "StubTokenMinter minted a fake bearer token. This must never run "
            "in production; wire the Vault-backed InternalTokenMinter first.",
            RuntimeWarning,
            stacklevel=2,
        )
        return f"stub.read.{customer.value}"


_GUIDANCE = {
    401: "The session is no longer authorized; ask the customer to reconnect Postern.",
    403: "This account is not covered by the current consent; call start_session.",
    404: "No such record. List the available refs with the matching list tool first.",
    429: "The backend is rate limiting this client. Wait before retrying.",
}
_DEFAULT_GUIDANCE = "The backend could not answer right now. Tell the customer and retry later."


def _validate_path(path: str) -> None:
    """Rejects anything that is not a same-host, rooted, non-traversing path.

    `httpx2.AsyncClient(base_url=...)` merges a *relative* path onto the base
    URL, but an absolute URL passed to `.get()` replaces the base entirely.
    Empirically confirmed (dev-docs/decisions/0001's sibling spike, same
    `httpx2.MockTransport` technique): `client.get("https://evil.example/x")`
    against a client built with `base_url="https://backend.test"` reaches
    `evil.example`, carrying whatever `headers=` the call set -- including
    `Authorization`. `client.get("//evil.example/x")` (protocol-relative) was
    also tested and, in `httpx2` 2.12.0, stays on the base host, but that is
    an implementation detail of this version, not a documented guarantee, so
    it is rejected too. A literal `..` segment (`/accounts/../../etc/passwd`)
    stays on the base host in this version but still escapes the intended
    path prefix; percent-encoded traversal (`%2e%2e`) is not collapsed by
    `httpx2` and is left as a literal, opaque path segment, so only the
    literal form is checked here.

    Every call site today builds `path` from a `Ref`-validated value, so this
    is defence in depth, not the primary control: nothing in this codebase
    passes attacker-controlled text as `path`. It is cheap enough to keep
    that true if it ever stops being deliberately so.
    """
    split = urlsplit(path)
    if split.scheme or split.netloc:
        raise ValueError(
            "path must be relative to the backend base URL, got an absolute "
            f"or protocol-relative URL: {path!r}"
        )
    if not path.startswith("/"):
        raise ValueError(f"path must be rooted (start with '/'): {path!r}")
    if ".." in path.split("/"):
        raise ValueError(f"path must not contain '..' segments: {path!r}")


class BackendClient:
    def __init__(
        self,
        base_url: str,
        minter: TokenMinter,
        *,
        transport: httpx2.AsyncBaseTransport | None = None,
        timeout: float | httpx2.Timeout = 10.0,
        before_backend_request: BackendRequestHook | None,
    ) -> None:
        # `timeout` widened from a bare `float` to also accept `httpx2.Timeout`
        # (Task 12 finding): a single float here applies independently to
        # httpx2's connect, read, write and pool phases, not once total, so
        # this constructor's own default of `10.0` was a worst case of up to
        # 40 seconds, not 10. `services/api/main.py` now always passes an
        # explicit `httpx2.Timeout` built from four `Settings` fields with a
        # stated combined worst case; this widening is only a type-hint
        # correction, `httpx2.AsyncClient(timeout=...)` already accepted a
        # `Timeout` instance.
        self._minter = minter
        # REQUIRED with no default, though `None` is a legitimate value: the
        # rule `postern_core.store.audit.append` applies to its own
        # parameters one layer down, for the same reason. A hook left off
        # reaches the operator's backend with nothing recorded first, which
        # is exactly the hole it exists to close, and a defaulted parameter
        # lets a future construction site inherit that silently instead of
        # writing the decision down.
        #
        # `None` stays legal because this package has callers with genuinely
        # nothing to record: every façade unit test in
        # `tests/test_facade_client.py` builds a client with no audit
        # middleware behind it. Defaulting it to the real hook instead would
        # be worse than either -- `postern_core.facade` would have to import
        # `services.api`, inverting the layering this package exists to keep
        # one-way.
        #
        # What still is not enforced: that the API service passes a non-None
        # one. `services/api/main.py::create_app` does, and
        # `tests/test_audit_entry_row.py::test_create_app_wires_the_entry_
        # write_into_the_backend_client` fails if it stops.
        self._before_backend_request = before_backend_request
        self._client = httpx2.AsyncClient(
            base_url=base_url,
            transport=transport,
            timeout=timeout,
            # Deliberate, not `httpx2`'s own default (which is also `False`
            # in 2.12.0): a 3xx from a compromised or misconfigured backend
            # must not carry the `Authorization` header to wherever
            # `Location` points.
            follow_redirects=False,
        )

    async def get_json(
        self,
        path: str,
        *,
        customer: CustomerRef,
        audience: str = "accounts.svc",
        params: Mapping[str, Any] | None = None,
    ) -> Any:
        _validate_path(path)
        token = self._minter(customer, audience)
        if self._before_backend_request is not None:
            # LAST, with nothing between it and the request but the request
            # itself. Path validation and minting are local work that touches
            # no customer data, so a failure in either leaves nothing to have
            # recorded; from this line on, the next thing that happens is a
            # socket carrying this customer's identity to the operator's
            # backend. Not guarded by try/except on purpose: see
            # `BackendRequestHook` on why a hook that raises must stop the
            # request rather than be logged past.
            await self._before_backend_request()
        response = await self._client.get(
            path, params=params, headers={"Authorization": f"Bearer {token}"}
        )
        if response.status_code >= 400:
            detail = _detail(response)
            raise BackendError(
                response.status_code, detail, _GUIDANCE.get(response.status_code, _DEFAULT_GUIDANCE)
            )
        return response.json()

    async def aclose(self) -> None:
        await self._client.aclose()


def _detail(response: httpx2.Response) -> str:
    """Scrubbed, length-capped summary of a backend error body.

    Scrubbing runs on the full body *before* the 200-character cut: cutting
    first could split a PAN or IBAN in half, leaving an unmasked digit
    fragment past the cut instead of a masked value before it.
    """
    try:
        body = response.json()
    except ValueError:
        text = response.text
    else:
        text = str(body.get("detail", body)) if isinstance(body, dict) else str(body)
    return _scrub(text)[:200]

# Writing a Postern Module

A module adds tools to Postern without forking this repository. It is an installed
Python distribution that declares an entry point; the two services discover it at
import time and register whatever it declared.

Read the trust section at the bottom before you install anyone's module, including
your own. A module runs in the same process as the signing key.

## One module, two distributions

A module that adds a write operation has two halves, and they load into two
different processes:

| Half | Entry-point group | Loaded by | Declares |
|---|---|---|---|
| read | `postern.read_modules` | `services/api` | MCP tools |
| write | `postern.write_modules` | `services/confirm` | backend routing per tool name |

They must ship as **two distributions**. `services/api` holds a READ signing key
and `services/confirm` a WRITE key, and the container images copy the virtualenv
whole, so one wheel declaring both groups would put backend write routing inside
the read container regardless of what the Dockerfile copies.
`refuse_distributions_declaring_both_halves` in `postern_core/modules/read.py`
refuses that shape, and the read service will not start.

The shipped example is the cards family: `packages/postern-cards` (read,
`cards.list`) and `packages/postern-cards-write` (write, `cards.freeze_card`,
`cards.unfreeze_card`, `cards.set_label`).

## The read half

```toml
# pyproject.toml of your read distribution
[project]
name = "acme-standing-orders"
dependencies = ["postern-core"]

[project.entry-points."postern.read_modules"]
standing_orders = "acme_standing_orders:MODULE"
```

```python
# acme_standing_orders/__init__.py
from postern_core.modules.read import ReadContext, ReadModule, ReadTool, ToolHandler


def _build_list(context: ReadContext) -> ToolHandler:
    async def standing_orders_list() -> list[StandingOrder]:
        """List the customer's standing orders with their refs and amounts.

        This docstring is what the model reads. FastMCP takes the tool's
        description from it and its input schema from the signature.
        """
        payload = await context.backend.get_json(
            "/standing-orders",
            customer=context.resolver(),
            audience="payments.svc",
        )
        return [_project(row) for row in payload["standing_orders"]]

    return standing_orders_list


MODULE = ReadModule(
    name="standing_orders",
    tools=(
        ReadTool(
            name="standing_orders.list",
            consent_domain="payments",
            build=_build_list,
        ),
    ),
)
```

`ReadContext` carries exactly two things: `resolver`, which answers which customer
this call is for, and `backend`, a read-only facade over the operator's backend
that mints internal READ tokens. Nothing else. It does not carry the database, a
key source or a token minter.

`audience` must be a key of `READ_SCOPES` in
`packages/postern-core/src/postern_core/auth/read_minter.py`, which maps it to the
read scope the internal token carries; any other audience raises `KeyError` when the
token is minted. The example above uses `payments.svc`, which maps to `payments:read`
(decision 0022): a read module carries a `payments:read` token; whether it can
reach only read routes depends on your gateway checking key and scope per path.

Your handler is a plain async function. You never touch `@mcp.tool`,
`mcp.types.ToolAnnotations` or the `auth=` parameter: the host does the
registration, which is why a FastMCP major release does not break every module.
You declare two booleans instead, `read_only` (default `True`) and `open_world`
(default `False`).

## The write half

```toml
[project]
name = "acme-standing-orders-write"
dependencies = ["postern-core"]

[project.entry-points."postern.write_modules"]
standing_orders = "acme_standing_orders_write:MODULE"
```

```python
from postern_core.domain.verification import VerificationTier
from postern_core.modules.write import WriteModule, WriteOperation

MODULE = WriteModule(
    name="standing_orders",
    operations=(
        WriteOperation(
            tool_name="standing_orders.cancel",
            audience="payments.svc",
            path_template="/standing-orders/{order_id}/cancel",
            method="POST",
            tier=VerificationTier.APP_APPROVAL,
        ),
    ),
)
```

No handler, no tool, no code that runs during a request. A write half declares
routing only. The approval callback in `services/confirm/callback.py` is what
reaches the endpoint, after the customer approves on their own device and the
service verifies an Ed25519 signature over the stored challenge row. That is
Postern's hard rule: execution belongs to the approval callback, never to a tool
handler.

`audience` must have an entry in `WRITE_SCOPES` in `services/confirm/minter.py`,
or minting raises. `tier` is declared, never derived from `method`: tier 1 is app
approval and the default for writes; tier 2 adds server-side identity
verification and is for payments, new payees, high value and limit increases.

## What the host gives you, and what it takes

Free, and not optional:

- **Consent.** Declare `consent_domain` and the host wraps your tool in the
  Postgres-backed check. FastMCP applies it in both `tools/list` and
  `tools/call`, so a tool your customer has not consented to is neither listed
  nor callable. `consent_domain=None` means no consent row is required; only
  `start_session` has any business declaring it.
- **Audit.** Up to two `audit_log` rows per call, correlated by `call_id`, one
  committed before the operator's backend is reached and one after the call
  finishes. Both are fail-closed: a failed audit write fails the call. Your
  handler sits inside that middleware and writes nothing.
- **Masking.** The domain types in `postern_core/domain/masking.py` mask on
  construction, so a handler that forgets fails validation instead of leaking.
- **Risk.** Per-session budgets and IP anomaly detection run in middleware. Call
  `get_current_session()` from `postern_core.risk.session` and record your row
  count if you want the budget to see your tool's reads.

Taken, and this is the part module authors are surprised by:

- **`tests/test_masking_golden.py` enumerates whatever the assembled server
  registers.** Adding a tool without a golden masking fixture fails the build.
  That is deliberate. A new domain shipping with no leak fixtures is the failure
  the gate exists for.
- **`tool-surface.json` must be regenerated.** `make tool-surface` rewrites it and
  `tests/test_tool_surface_golden.py` fails until the checked-in file agrees with
  the assembled server. The diff is the point: it names the tool, the module, the
  consent domain, the annotations, the parameters, and every write operation's
  audience, path, method and tier.
- **Every registered tool must be annotated read-only** on the read path, and no
  tool parameter may be typed `MaskedPan` or `MaskedIban`.

## What the loader refuses

The read service will not start if:

- one distribution declares both entry-point groups;
- two modules declare the same tool name, or a module declares a name a built-in
  already declares;
- an entry point resolves to something that is not a `ReadModule`;
- importing a read module pulled `postern_core.modules.write` into the process,
  which is how a single module would smuggle its write half onto the read path.

The write service will not start if two modules route the same tool name, or if a
module routes a tool name this repository already routes as a built-in.

Every one of those is a property of what is installed, so a process that starts is
a process whose module set was accepted. None of them is checked per request.

## Trust: a module is not sandboxed

A module runs in the same process, in the same interpreter, with the same memory
as the service that loaded it. Python offers no boundary that would change this,
and Postern has deliberately not built a partial one.

A module you install can, with no exploit and no bug on anyone's part:

- read the signing key material the process holds, because the key source objects
  in `postern_core/auth/keys.py` are reachable by ordinary attribute access;
- mint an internal JWT for any audience the loading process has a key for;
- read or write any row the process's database credential can reach, `audit_log`
  inserts included;
- monkey-patch masking, consent or audit, because nothing is immutable at runtime;
- open a socket to anywhere the container's egress policy allows.

The read process holds a READ key and cannot mint a write token, so a module
installed only on the read path cannot move money. That bound comes from the key
split and from the read image not carrying the write half. It does not come from
anything in this seam. A module installed on the write path is inside the write
blast radius in full.

**Installing a module is exactly as consequential as merging a commit into this
repository.** Review it, pin it by hash, build it into your own image, and do not
let the installed module list be something a deploy can change without a diff.
`tool-surface.json` makes the surface reviewable. Nothing makes the code
reviewable except reading it.

This is not a permission model, a capability system, a sandbox, or a step towards
one. Those are a separate and much larger question, and a partial sandbox is worse
than this warning, because it invites the trust this page is refusing.

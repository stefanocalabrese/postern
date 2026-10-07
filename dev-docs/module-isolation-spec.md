# Module isolation: what it would take to make a module untrusted

**Date:** 29 September 2026
**Status:** specification. Nothing here is built. No production code was written for it.
**Against:** the in-process module seam shipped in `71e2f94`, recorded in
`dev-docs/decisions/0018-module-seam.md`.

---

## Verdict, first

**Do not build process or container isolation for modules. Two cheaper things
buy more, and both are already owed to the operator.**

The seam's honest limit is that a module reaches the signing key and the database
credential by attribute access. Isolation would take those away from a module. It
would not take them away from the 104 installed distributions that hold them by
exactly the same route: `joserfc` signs the internal JWT, `asyncpg` holds the
database credential, `fastmcp` dispatches every call. An operator who installs a
module after reading it, pins it by hash and builds it into their own image, which
is what record 0018 and `docs/user-guide/writing-a-module.md` already require, has
the same exposure to the module as to a `pydantic` point release. Spending four to
six weeks on a boundary around one of 105 in-process actors is not a security
improvement, it is a relocation.

What removes the two assets for modules **and** for the other 104:

1. **Move signing out of process memory.** `FileKeySource` reads a PEM from disk
   today. Vault's transit engine signs without releasing a key, and Vault is
   already item 6 on the operator checklist. Then no in-process actor can read a
   key, because the process holds none. Cost: one network hop per internal token
   mint, inside an existing 10.0 s backend budget.
2. **Split the database role.** Item 11 on the same checklist. An application
   login role holding `SELECT, INSERT` on `audit_log` and owning nothing bounds
   every in-process actor at once.

If you want a genuinely untrusted module before either lands, build the
declaration-only module in §12: a module with no code at all, which is the only
Python sandbox that works. Roughly 500 lines and one gate, and it covers the
`<domain>.list` / `<domain>.get_<x>` shapes that four of the five shipped tools
already are.

The rest of this document specifies the full boundary anyway, because the owner
asked for the shape and the cost, and because §13 names the one condition that
would flip the recommendation.

---

## 1. What a module holds today, and what isolation would take

`ReadContext` carries two fields, the customer resolver and the backend reader.
That is the intended surface. The actual surface is the process, and the seam's
own documentation says so. Three routes, in ascending order of how little a
reviewer would notice:

| Route | What it reaches |
|---|---|
| `import postern_core.auth.keys`, then read the app's `KeySource` off any object that holds it | the READ signing key, then any internal JWT for any audience |
| `open(read_key_pem_path)` | the same key, from disk, no import graph involvement |
| `gc.get_objects()` | every live object in the interpreter, including the `Database`, regardless of what the module imported |

The third one matters for the spec because it sets the floor. Record 0018 says the
key source is "reachable from any imported module through ordinary attribute
access", which understates it: `gc.get_objects()` walks the heap and needs no
import at all. So no import-graph control, no `sys.addaudithook`, and no
`RestrictedPython` variant is a boundary. Nothing short of a separate address
space is.

---

## 2. The boundary

| Candidate | Removes | Keeps | Verdict |
|---|---|---|---|
| In-process (today) | nothing | everything | current |
| Import hooks, audit hooks, `RestrictedPython` | nothing (see `gc.get_objects()`) | everything | **reject.** This is the "half-sandbox worse than the warning" record 0018 refuses |
| Subprocess, same container, same UID | host memory, the `Database` object | the PEM on disk, the network namespace, `/tmp`, the env vars | **reject.** `FileKeySource` reads a PEM from a path the child can also open. A process boundary that leaves the key readable removes the inconvenience, not the capability |
| Sidecar container, same ECS task | host memory, the filesystem, the env vars | the network namespace, therefore the egress policy and any reachable endpoint | **accept.** The PEM is gone, which is the point |
| Separate ECS service, own task role, own security group | all of the above plus egress | nothing worth naming | strongest, and §10 prices it |
| WASM (`wasmtime` + Pyodide) | everything, by construction | | **reject.** A module stops being arbitrary Python: CPython-on-WASM start-up is hundreds of milliseconds against a 55 ms native subprocess, and a module needing a C-extension dependency cannot ship |

**Recommendation: the sidecar container, one per module.** Not one shared worker
for all modules: two mutually untrusted modules in one address space can read each
other's customer data, so pooling them re-creates the problem one layer down.

Note what the sidecar does **not** buy. Containers in one ECS task share a network
namespace, so a module container has the same egress reach as the host container.
It cannot reach a backend write endpoint, but that is because it holds no write
key, exactly as today. The boundary is about assets, not about the network, which
is the same thing CLAUDE.md says about PrivateLink.

---

## 3. The transport

**Newline-delimited JSON-RPC 2.0 over a length-prefixed stream: `AF_UNIX` for the
subprocess shape, loopback TCP for the sidecar shape.** One `id` per call,
multiplexed over one connection, with an explicit `deadline_ms` field in every
request.

Measured on this machine, a 1552-byte request and a small response, including two
JSON encodes and two decodes: **p50 0.043 ms, p99 0.055 ms, max 0.146 ms** over
3000 calls. Host-side re-validation of a 12-row `Account` list with the masking
validators running: **0.043 ms p50**. Adding both to a tool call costs about
0.09 ms against a 101.0 s request deadline. **Latency is not an argument against
isolation in either direction.**

Rejected:

- **`pickle`, `multiprocessing` default serialisation, any shared-memory object
  graph.** Unpickling runs code the sender chose. The boundary would execute the
  module's bytes inside the host, which inverts the whole exercise.
- **gRPC and protobuf.** A `grpcio` C-extension dependency and a codegen step for
  a payload measured in kilobytes. The schema discipline it sells is already held
  by `tool-surface.json` plus pydantic.
- **stdin/stdout as the data plane.** One `print()` in module code corrupts the
  frame stream. If you use pipes, use a dedicated pair of file descriptors and
  leave 0, 1 and 2 to the module for logging.
- **MCP.** §11.

---

## 4. What the module gets: the crux

Two designs. They make a module a different kind of thing.

### Design A: the host fetches, the module transforms

The module declares, per tool, which backend endpoint it needs (audience, path
template, query parameters) and an output schema. The host makes the call through
`BackendClient`, hands the parsed JSON across the boundary, receives a JSON object
back, and validates it into a host-built pydantic model. The module holds no
credential of any kind.

This is the read half becoming what the write half already is. `WriteOperation`
declares audience, path template, method and tier, and no code. A module's write
half supplies nothing that runs on a request today, so **isolation is a read-path
question only** and the write service needs no worker at all.

### Design B: the host mints a scoped credential, the module is still a client

The host mints a short-lived internal JWT restricted to one audience and one path
prefix, hands it over, and the module calls the backend itself.

**Design A, and three reasons that are not preferences.**

1. **The pre-touch audit row cannot survive B.** `BackendRequestHook`'s contract
   is that if the hook raises, the request is not made, and the whole value of it
   is that a caller which cannot record the touch can stop it. Only the party
   opening the socket can honour that. Under B the `outcome='reaching'` row
   becomes a promise a module makes, which record 0006 spent a decision on making
   fail-closed. Under A it keeps working untouched, because the host still makes
   the call.
2. **A path-scoped token is a claim no backend honours.** The internal token is an
   RFC 8693 delegation shape with `sub` = customer and `act.sub` = service, and
   ZT-2 is the still-unanswered requirement that domain services scope on `sub`.
   Adding a path-scope claim means the domain teams must enforce a second claim
   they have not yet been asked about the first one. That is a new cross-team
   dependency on the critical path.
3. **A cannot lie about data the host also has.** This is the part that surprised
   me and it is the strongest argument for A. Because the host fetched the payload,
   the host holds both sides and can check the module's output against its input
   without knowing the right answer: every `Ref` returned must appear in the
   payload, every currency must appear in the payload, the row count must not
   exceed the payload's row count. Those checks catch fabrication. They are
   impossible under B, where the host never sees what the backend said.

**What B would cost if you built it anyway,** stated so it is not left implied:
`decision_scope(False)`, the contextvar that lets the revocation layer refuse a
mint mid-call, stops applying, because the minting no longer happens in the
process that published it. Each module needs its own connection to the Istio
gateway, so PrivateLink reach multiplies by the module count. And the module can
read any backend read endpoint in its audience, not just the ones it declared,
unless the backend enforces the path scope from (2).

---

## 5. Where masking lands

**Host-side, and it already is.** Masking happens in exactly one place: a pydantic
`AfterValidator` running during model construction, in `MaskedPan`, `MaskedIban`
and `FreeText`. Nothing else on the response path masks anything. A handler that
returns a plain `dict` leaks whatever the backend sent, which is why the golden
harness has a self-check that builds a leaky tool and asserts the harness catches
it.

Under Design A the host constructs the model, so masking is a property of the
boundary rather than of the module author's memory. That requires the module's
output shape to be **declared data, not returned objects**:

```
ReadTool(
    name="standing_orders.list",
    consent_domain="payments",
    request=BackendRequest(audience="payments.svc", path="/standing-orders"),
    returns=RowsOf({
        "ref":        "ref",           # Ref, pattern ^[a-z]{3}_[A-Za-z0-9]{1,32}$
        "label":      "free_text",     # FreeText, PAN/IBAN substrings redacted
        "iban":       "masked_iban",   # MaskedIban, mod-97 checked then masked
        "amount":     "money",         # Money, explicit currency
        "next_at":    "datetime",
    }),
)
```

The host builds the model with `create_model` from that table, keeps
`extra="forbid"` and `hide_input_in_errors` from `_Strict`, and routes the
construction through `build_model` so a validation failure reports field names and
never the value. The type vocabulary is closed: `ref`, `free_text`,
`masked_pan`, `masked_iban`, `money`, `datetime`, `bool`, `int`, `enum[...]`. A
module wanting a new field type needs a host release. **That is the real cost of
this design and it is the one to argue about**, not the transport.

**Why a closed vocabulary rather than a better leak detector.** The golden gate
runs exactly two regexes, a digit run of 12 or more and an IBAN shape of 14 to 34
characters. It does not catch a full name, an email, a date of birth, a phone
number, a passport number (2 letters plus 7 digits is below the IBAN floor), or a
9-digit national ID. Widening the regexes is a losing game against an author who
chooses the field. Constraining the declared type is not: a field declared `ref`
cannot carry a name, because the pattern rejects it. The gate stays as a backstop
for the fields that are `free_text` by necessity.

**Errors are an output channel too.** The golden harness scans the `content`
blocks precisely because FastMCP puts `str(exc)` into a text block on an error
result. So the host must never forward a module's exception text. Spec: the module
returns a code from a closed set plus an optional detail, and the host passes the
detail through `scrub_tree` under a `redaction_budget` scope and caps it at 200
characters, which is what `_detail` already does for a backend error body.

---

## 6. What stays host-side, verified rather than assumed

| Control | Mechanism | Survives Design A |
|---|---|---|
| Consent | `consent_for` returns an async predicate the host passes as `auth=`; FastMCP evaluates it in both `tools/list` and dispatch, 5 evaluations per real call, cached on `request.state`, fails closed on a store error | **Unchanged, free.** It is a pre-dispatch gate and never sees the handler |
| Revocation | `RevocationMiddleware` on `on_call_tool` and `on_list_tools`, keyed on `sub`, `client_id`, `jti` | **Unchanged.** `decision_scope` also survives A, because minting stays host-side |
| Deadline | `RequestDeadline`, outermost ASGI middleware, 101.0 s, cancels the task and answers 504 with JSON-RPC `-32001` | Unchanged, and §7 makes the module's budget fit inside it |
| Audit, completion row | `AuditMiddleware.on_call_tool` wraps `call_next` in `try/except` and writes `outcome` from whether it raised | **Survives with one hard requirement.** The host's RPC stub must **raise** on module failure, never return an error value. The middleware docstring records, measured 2026-09-14, that the `isError: true` envelope is built above the chain, so a hook reading `result.is_error` counts zero failures. A stub that returns instead of raising would record every module crash as `OUTCOME_RETURNED` |
| Audit, reaching row | A `_pending_entry` contextvar set in `on_call_tool` and read by `record_data_touch`, wired as the facade's `before_backend_request` | **Unchanged under A, lost under B.** Both ends stay in the host process |
| Risk, admission and settle | `RiskMiddleware` keyed on `SessionKey(customer_ref, client_id)`, evaluated before and after `call_next` | **Unchanged** |
| Risk, row counting | The handler calls `get_current_session()` and mutates the shared `RiskContext` through a contextvar | **Breaks.** A contextvar does not cross a process. **The replacement is better than what it replaces:** the host counts rows off the validated output it just built and records them itself, so a module cannot leave ZT-5 blind to bulk extraction through it. Record 0018 lists exactly that as an uncaught quiet failure of the current seam |

One control improves, one needs a stub that raises, the rest are free. The
expensive parts of isolation are elsewhere.

---

## 7. Failure modes the host now owns

Today a bad module takes the process down, which is loud. Replacements:

**Crash.** The host sees EOF or a non-zero exit. The stub raises, so the audit
completion row records `OUTCOME_RAISED` with the exception type. Supervision:
restart with backoff, measured cold start 55 ms for a worker importing `pydantic`
and the domain models. After N restarts in a window, mark the module **degraded**
and have its tools stop being listed. That needs no new mechanism: the host
already passes a per-tool async predicate as `auth=`, and FastMCP evaluates it in
`tools/list` as well as in dispatch, so module health composes with the consent
check on the same seam.

**Hang.** A deadline, and the arithmetic has to fit inside the existing one. The
101.0 s request deadline is derived from real worst cases: five consent lookups at
13.0 s, the entry audit row at 13.0 s, the backend call at 10.0 s, the completion
row at 13.0 s. A module transform gets the same treatment, which means a declared
number, not a share of the remainder. **Proposed: 2.0 s, and the request deadline
becomes 103.0 s.** The module worker holds no database connection and no backend
socket under Design A, so the pool ceiling of 5 plus 10 overflow plus the audit
reserve of 1 is untouched, and the "2 to 7 checkouts, one at a time" shape record
0013 measured does not change.

On expiry the host must **kill the worker, not reuse it.** A worker cancelled
mid-frame leaves the stream at an unknown offset, and reusing it risks answering
call N with call N+1's body. That is a correctness argument, not hygiene. It also
means a 2.0 s timeout costs a 55 ms restart, which is affordable.

**Malformed output.** Host-side pydantic validation through `build_model`, which
already turns a `ValidationError` into a status-502 `BackendError` carrying no field or
value, for the reason that module's docstring gives about FastMCP's own logger.

**A valid-looking wrong answer.** Not detectable, and the spec should say so
plainly rather than gesture at defence in depth. A module that returns the wrong
balance for the right account is indistinguishable from a backend that does. What
the host **can** check, because under Design A it holds the payload the module was
given, is fabrication: every `Ref` in the output appears in the input, every
currency appears in the input, the row count does not exceed the input's. Those
are three cheap assertions and they draw a real line. Corruption inside that line
stays undetectable, and no boundary changes it.

---

## 8. The tool surface

`tool-surface.json` is regenerated from the assembled server by
`tools/write_tool_surface.py` over `tests/tool_surface.py::surface_json`, and
`tests/test_tool_surface_golden.py` fails until the checked-in file agrees: 5 read
tools and 6 write operations today. The static-declaration rule and the both-ways
cross-check hold under isolation, and one thing about discovery must change.

**Discovery must stop importing.** `EntryPoint.load()` imports the module, which
runs module code inside the host at composition time. That is full trust before
the boundary exists, so the declaration cannot be a Python object any more. It
becomes a manifest read out of the distribution's metadata without importing:
enumerate `entry_points(group=...)` for the `.value` only, then read the manifest
through `importlib.metadata.Distribution.locate_file` or `read_text`, neither of
which touches the import system.

Consequence to write down: **an isolated module is a different artifact, not the
same wheel with a flag.** The read half's `ReadModule` object cannot be reused,
because resolving it is the thing being removed. The four loader refusals port
across as manifest validation, and one of them gets simpler: with no module code
on the read path, `_refuse_write_half_in_the_read_path` is checking for an import
that can no longer happen.

The manifest must also pin the code, by wheel hash or image digest, because the
manifest is what a reviewer diffs and the transform is what actually runs.

---

## 9. What isolation still does not give you

- **Prompt injection through a tool description.** A module's description is text
  the model treats as instruction, and it reaches the client whether or not the
  handler is in another process. The manifest makes it diffable, which is what
  `tool-surface.json` already does.
- **A mis-declared consent domain.** A module declaring `consent_domain="accounts"`
  for a tool that reads cards is gated on the wrong customer decision, and the host
  cannot tell. Under Design A the host also knows the audience, so it could refuse
  a mismatch against a host-side table of domain-to-audience pairs. That check is
  worth more than the boundary and costs about 20 lines.
- **Data the golden gate's two regexes do not match.** §5.
- **A superuser, or anything the database role can do.** Item 11 is unchanged by
  any of this.

---

## 10. Cost

| | Today | Design A, sidecar per module |
|---|---|---|
| Latency per tool call | baseline | +0.09 ms measured (0.043 ms round trip, 0.043 ms revalidation) |
| Containers per read task | 1 | 1 + one per installed module |
| Containers, write path | 1 | 1. The write half declares no code |
| `docker compose` services | 5 (`db`, `backend-stub`, `migrate`, `api`, `confirm`) | 5 + one per module in the local stack |
| Dockerfile | 6 stages, 3 targets, the venv copied whole into each | a seventh stage per module, and `refuse_distributions_declaring_both_halves` stops mattering because no module code is in the serving image |
| Worker restart | n/a | 55 ms measured |
| Debugging a module | a Python traceback in the host's log | a serialised fault. The worker's traceback must reach the host's log and must never reach the model, so you own two log paths and a correlation id |
| `make ci` | 7 targets, 2783 tests, 178 to 180 s with Docker up (two runs, 29 September 2026) | the in-process `Client(transport=server)` path stops covering module tools. Either every module test spawns a worker, or a session-scoped worker fixture spawns once at 55 ms. Session-scoped is the only affordable option, and it means module tests share worker state |
| Concurrency | asyncio in one process | one worker serialises its module's calls unless the worker is itself async. A module transform that blocks blocks every concurrent call to that module, so "your transform must not block" becomes a rule you enforce with nothing |

The last row is the honest cost. It is not latency and it is not containers, it is
that you have added a supervision problem, a second log path, a session-scoped
test fixture that shares state, and a rule about blocking that no gate can check,
in exchange for a boundary around 1 of 105 in-process actors.

---

## 11. Module as an MCP server that Postern proxies

It does look elegant, and it fails two checks.

**Against the runtime-registration rule.** If Postern asks the module server for
its `tools/list`, the surface comes from a network response: it can differ between
two replicas of one image, it is not resolvable before the first request, and
`git diff` shows nothing. That is what CLAUDE.md forbids and it is a worse version
of the config-file alternative record 0018 already rejected. You could keep the
manifest and use MCP only as transport, at which point MCP is buying you a
JSON-RPC framing you were going to write in a day, plus three mandatory headers,
plus a protocol where a tool error is an HTTP 200 with `is_error` set, which is
precisely the distinction the host needs to tell a module crash from a module
answer.

**Against the PrivateLink direction.** A loopback sidecar speaking MCP is
harmless. The problem is what the shape suggests: an operator told "a module is an
MCP server" will host it where MCP servers go, which is behind a gateway,
reachable, possibly run by the module's vendor. Then the operator's customer data
leaves the VPC to be transformed by a third party, and the inbound path the seam
was designed to avoid exists after all. The failure is social rather than
technical, and it is the likelier one.

**Verdict: reject.** The one real attraction, that an operator could exercise a
module with `npx @modelcontextprotocol/inspector`, is not worth either.

---

## 12. Is the threat model real?

Put the two populations side by side.

| | A module author | `joserfc`, `asyncpg`, `fastmcp`, and 101 others |
|---|---|---|
| Runs in-process | yes | yes |
| Reads the signing key | yes | yes, same attribute access |
| Reaches every `audit_log` row the credential can | yes | yes |
| Monkey-patches masking or consent | yes | yes |
| Pinned and reviewed | "review it, pin it by hash, build it into your own image" | `uv lock`, `uv lock --check --offline` in `make ci` |

The columns are the same. Three asymmetries are real, and only one of them is
load-bearing:

1. **Targeting.** A `pydantic` maintainer has no interest aimed at this bank's
   customers. A payments-module author on a bank-data marketplace has a specific
   one. Real, and it changes likelihood rather than capability.
2. **Blast radius per artifact.** Identical. Both are arbitrary code in the
   process.
3. **Review cadence, and this is the one that decides it.** A dependency bump is a
   commit against `uv.lock` that a reviewer sees. A marketplace's entire premise is
   that the module list changes more often, and with less reading, than the
   lockfile. If the operator reviews a module exactly as they review a lockfile
   bump, which is what record 0018 instructs, then the two threat models are the
   same one and isolation buys nothing.

So: **isolating modules while installing 104 distributions is incoherent, unless
the operator intends the module list to be mutable outside the lockfile review
path.** Today's documentation says the opposite, in bold, twice. The seam is
consistent with its own instructions. The gap is not in the code, it is that an
open marketplace would contradict the instructions, and the fix for that is to
either not have one or accept the consequence in writing.

**The coherent alternative,** and the reason the verdict at the top is what it is:
attack the assets, not the actors. Vault transit signing removes the key from the
process for all 105 at once. A split database role removes the credential's reach
for all 105 at once. Both are already on the operator checklist. Neither needs a
supervision loop, a second log path, or a rule about blocking.

### The declaration-only module, if you want one anyway

A module that ships **no code** needs no boundary, because there is nothing to
isolate. Take Design A's declaration and drop the transform: audience, path
template, parameters, and a field map from backend JSON keys to the closed type
vocabulary in §5. The host does everything. There is no worker, no deadline, no
supervision, no compose change, and `make ci` tests it in-process exactly as it
tests a built-in today.

Honest bound: it covers a list and a get, which is what four of the five shipped
tools are. It does not cover the `MAX_ROWS` and `truncated` handling in
`transactions.list`, pagination, two-call composition, or a derived field. Those
need code, and code needs §2 through §10.

Estimate: a manifest schema, a loader that validates it without importing, the
`create_model` builder, the audience-to-domain check from §9, and a golden-surface
extension. About 500 lines and one gate, against four to six weeks for the
boundary.

---

## 13. What would change the answer

One condition, and it is checkable: **a named third party whose module the
operator will install without reading its source.** Not "a marketplace one day".
A vendor, a wheel, and a decision not to review it.

Until that exists, the module seam's warning is accurate, the operator's
instructions are consistent with it, and the two items that actually reduce
exposure are items 6 and 11 on a checklist that already has them.

If it does exist, build in this order, and stop at each step to see whether it was
enough: the declaration-only module in §12; then the audience-to-domain consent
check in §9; then Design A with a sidecar per module, the raising stub from §6, the
2.0 s deadline and kill-on-timeout from §7, and the manifest discovery from §8.
Design B stays rejected at every step, because the pre-touch audit row is not
negotiable.

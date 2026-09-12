# 0001: Façade HTTP client is `httpx2`; `respx` is dropped

**Date:** 2026-09-12

## Question

`fastmcp` 4.0.3 depends on `httpx2>=2.5.0` and declares no dependency on `httpx`.
`respx` 0.23.1 declares `httpx>=0.25.0`. Does `respx` intercept `httpx2` traffic,
or does the façade's tests need a different mocking approach?

## What was installed before this spike

```
$ uv run python -c "import httpx2; print(httpx2.__version__)"
2.12.0
$ uv run python -c "import httpx; print(httpx.__version__)"
0.28.1
```

Both imported. `uv tree --invert --package httpx` showed the only path to `httpx`
in the whole dependency graph:

```
httpx v0.28.1
└── respx v0.23.1
    └── postern v0.1.0 (group: dev)
```

`uv pip show httpx` confirmed: `Required-by: respx`. Nothing else in the project —
not `fastmcp`, not `mcp`, not any other dependency — pulls in `httpx`. It existed
solely because `respx` is in the `dev` group.

## Experiment 1: does `respx` intercept `httpx2`?

```python
import asyncio, httpx2, respx

async def main() -> None:
    with respx.mock(base_url="https://backend.test") as mock:
        mock.get("/ping").mock(return_value=httpx2.Response(200, json={"ok": True}))
        async with httpx2.AsyncClient(base_url="https://backend.test") as c:
            r = await c.get("/ping")
        print("intercepted:", r.json())

asyncio.run(main())
```

Output:

```
Traceback (most recent call last):
  ...
  File ".../respx/models.py", line 267, in mock
    self.return_value = return_value
  File ".../respx/models.py", line 200, in return_value
    raise TypeError(f"{return_value!r} is not an instance of httpx.Response")
TypeError: <Response [200 OK]> is not an instance of httpx.Response
```

`respx` does not silently fail to intercept — it hard-rejects an `httpx2.Response`
at mock-setup time with a `TypeError`, before any request is sent. `respx` is
built against `httpx` types, not the `httpx`/`httpx2` wire protocol, so it cannot
mock `httpx2` traffic under any configuration.

## Experiment 2: does `httpx2.MockTransport` work as a replacement?

```python
import asyncio
import httpx2

received: list[httpx2.Request] = []

def handler(request: httpx2.Request) -> httpx2.Response:
    received.append(request)
    return httpx2.Response(200, json={"ok": True})

async def main() -> None:
    transport = httpx2.MockTransport(handler)
    async with httpx2.AsyncClient(base_url="https://backend.test", transport=transport) as client:
        r = await client.get("/ping", headers={"Authorization": "Bearer test-token"})

    assert len(received) == 1
    assert received[0].headers["Authorization"] == "Bearer test-token"
    assert r.status_code == 200
    assert r.json() == {"ok": True}
    print("handler received request:", received[0].method, received[0].url)
    print("Authorization header seen by handler:", received[0].headers["Authorization"])
    print("client response:", r.status_code, r.json())
    print("ALL ASSERTIONS PASSED")

asyncio.run(main())
```

Output:

```
handler received request: GET https://backend.test/ping
Authorization header seen by handler: Bearer test-token
client response: 200 {'ok': True}
ALL ASSERTIONS PASSED
```

`httpx2.MockTransport` exists, intercepts real client calls, and gives the
handler the actual `Request` object with headers intact — including a custom
`Authorization` header set by the caller. This is the exact seam
`BackendClient(transport=...)` needs.

## Decision

The façade uses `httpx2`. It is FastMCP's own HTTP dependency, so this keeps one
HTTP stack in the image rather than two. Backend tests mock at the **transport**
layer by injecting `httpx2.MockTransport(handler)` into `BackendClient`, per
Experiment 2 above, not via `respx`.

`respx` is dropped from the `dev` dependency group. Evidence for dropping, not
just for `respx` failing on `httpx2`:

- `grep -rn "respx" --include="*.py" .` (excluding `.venv`) matched nothing —
  no test in the repository uses it.
- Every backend-mocking test already planned for Tasks 6, 8, 9, 10 and 11 in
  `docs/superpowers/plans/postern-foundation-and-read-surface-2026-09-12.md`
  is written against `httpx2.MockTransport`, not `respx` — the plan anticipated
  this outcome and did not depend on `respx` either way.
- `respx` was the *only* reason bare `httpx` was installed at all (see `uv tree`
  output above). Dropping it removes `httpx`, `httpcore`, and `certifi` as
  unused transitive dependencies: `uv lock` reported `Removed httpx v0.28.1`,
  `Removed httpcore v1.0.9`, `Removed certifi v2026.7.22`, `Removed respx v0.23.1`.
  A bank image carrying two independent HTTP client stacks, one of them unused
  outside its own now-removed test tool, is not something to keep around.

Change made: removed `"respx>=0.23"` from `[dependency-groups].dev` in
`pyproject.toml`, ran `uv lock` and `uv sync`. Post-change:

```
$ uv run python -c "import httpx2; print('httpx2 ok', httpx2.__version__)"
httpx2 ok 2.12.0
$ uv run python -c "import httpx"
Traceback (most recent call last):
  ...
ModuleNotFoundError: No module named 'httpx'
```

`make ci` (lint, fmt-check, type, imports, lock, test) exits 0 after the change.

## Consequence

- **Task 6** (`packages/postern-core/src/postern_core/facade/client.py`,
  `tests/test_facade_client.py`): `BackendClient` takes an
  `transport: httpx2.AsyncBaseTransport | None` constructor parameter; tests
  build the client with `httpx2.MockTransport(handler)`, as already written in
  the plan. No `respx` import.
- **Tasks 8, 9, 10, 11** (`accounts.list`/`accounts.get_balance`,
  `transactions.list`, `cards.list`, `banking_start_session`): their backend
  tests use `httpx2.MockTransport(_handler)` against fixture bodies, exactly
  as drafted in the plan. This is now the *only* supported approach, not an
  optional simplification — `respx` is no longer a dev dependency and cannot
  mock `httpx2` regardless.
- No task needs `respx` for anything else in this codebase; none was found.

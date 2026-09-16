# 0005: `MCP-Protocol-Version` selects the dispatcher, not just a validation check

**Date:** 2026-09-16

## Finding

Verifying Plan 2 Task 7 against the running compose stack (`docs/verification/
2026-09-16-consent-and-audit.md`) required sending `MCP-Protocol-Version:
2026-07-28` on every request, per CLAUDE.md's "Version traps". Checking why
that header is load-bearing, rather than assuming it, found the exact
routing in the installed `mcp` package
(`mcp/server/streamable_http_manager.py:192-198`):

```python
header = MCP_PROTOCOL_VERSION_HEADER.encode("ascii")
pv = next((v.decode("latin-1") for k, v in scope["headers"] if k == header), None)
if pv is not None and pv not in HANDSHAKE_PROTOCOL_VERSIONS:
    await handle_modern_request(...)
    return
# Dispatch to the appropriate handler
if self.stateless:
    await self._handle_stateless_request(pv, scope, receive, send)
```

A header value outside the legacy handshake versions routes to
`handle_modern_request`. Absent the header entirely (`pv is None`), the
condition is false and the request falls through to the **legacy stateless
handler** instead, seeded with `DEFAULT_NEGOTIATED_VERSION`.

Confirmed live against the running stack: an otherwise-identical `tools/list`
request with the header omitted returns `200` with the same tool names, but
the response is `{"jsonrpc":"2.0","id":9,"result":{"tools":[...]}}` --
missing `cacheScope`, `ttlMs` and `resultType`, the fields CLAUDE.md's hard
rule requires on `tools/list`. The legacy envelope simply does not carry
them; nothing in this repo's own code rejects the request or degrades
gracefully.

**What still worked without the header:** consent enforcement. A `tools/call`
for `accounts.list` and repeated denials of `cards.list` behaved identically
with and without the header -- filtering and rejection happen in FastMCP's
own `auth=` check above this dispatch split, not inside it.

**What did not get exercised:** whether the legacy path can reach
`handle_modern_request`'s structured `-32020` rejection at all, since that
branch is defined by "header present and not a handshake version" --
omitting the header is a third case (no header) this condition does not
route through modern dispatch either. `HeaderBodyValidation` (this repo's
own ASGI middleware) runs before any of this and does not check for
`MCP-Protocol-Version`, so a request missing it is never rejected by this
codebase's own control; it silently downgrades to legacy dispatch instead.

## Decision

No code change from this finding alone. Recorded so the next task that
touches `strict_headers` or the header/body validation middleware knows
`MCP-Protocol-Version` is not currently one of the headers
`HeaderBodyValidation` validates, and that its absence is a routing fork in
a third-party dependency, not a 400 in this codebase. Whether
`HeaderBodyValidation` should also enforce this header's presence once
`strict_headers` defaults to `True` (design decision D2, `docs/decisions/
0003-composition-root.md` §4) is left open, not decided here.

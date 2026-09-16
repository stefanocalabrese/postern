# 2026-09-16: what local testing can and cannot show about ZT-2 subject scoping

A cross-customer request against the local stub backend can now be made to
fail inside this repository, in `tests/test_stub_subject_scoping.py`. The
same cross-customer shape made through either of the two files backing the
masking and consent test suites still cannot fail, because neither file
calls the stub. Anyone reading "verified against the running stack" in this
directory should not read it as covering authorization, for any of the four
existing records: all four predate the stub's subject check.

## What this is, and what it is not

ZT-2 -- whether the bank's real domain services enforce on the JWT `sub`
rather than on an account identifier taken from the request
(`docs/bank-mcp-zero-trust-plan.md:100-110`, `CLAUDE.md:128`) -- is answered
by another team, about services that are not in this repo. Nothing below
touches that answer, moves it forward, or stands in for it. `stub/backend.py`
is a test double for the local `docker compose` stack and for one pytest
file; changing what it enforces changes what a local test can catch, not
what the bank's services actually do. This record exists so that boundary
does not get blurred by a later reader.

## Before: the stub answered every caller identically

Introduced in commit `0de52b1` ("build: two-target image, pinned bases, and
a working local stack", 2026-09-14), all four domain routes took the same
shape:

```python
async def accounts(_request: Request) -> JSONResponse:
    return JSONResponse(ACCOUNTS)
```

`_request` was never read, in `accounts`, `balance`, `transactions` or
`cards`. Every caller, with or without a token, naming any account or none,
received the same fixed `ACCOUNTS` / `BALANCE` / `TRANSACTIONS` / `CARDS`
body.

## Documented at the time: the account-substitution proof

`docs/verification/2026-09-16-redaction-budget-exhausted.md` (commit
`b3f6264`, run before the stub changed) made the call this record would
otherwise repeat, and it is cited here rather than restated as new. Its
"What was not, and could not be, verified this way" section (lines 463-479)
records a request naming `account_ref: "acc_4111111111114417"` coming back
with `"account_ref":"acc_7f3a"` -- the fixture's own account -- and `isError`
`false`. The same record's line 470 states the conclusion directly: "this
record proves nothing about whether a handler scopes its query to the token
subject." That is the exact gap this file's second half addresses -- and
only for one pytest file, not for the compose stack that record ran against.

## Now: `stub/backend.py` scopes on the internal token's subject

Commit `316b51c` ("stub: enforce on the internal token subject", 2026-09-16)
rewrote all four routes. Each one calls `_subject(request)`
(`stub/backend.py:160-191`) before touching any fixture, and returns 401
with no fixture value (`_unauthorized`, `stub/backend.py:113-125`) when
`_subject` returns `None`. `_subject` reads the `Authorization` header and
recognizes two shapes for the credential that follows `Bearer `:

- `StubTokenMinter`'s own literal output, `stub.read.<customer>`
  (`stub/backend.py:106`, matching
  `packages/postern-core/src/postern_core/facade/client.py:77`) -- the
  subject is whatever follows the `stub.read.` prefix.
- A JWT, read for its `sub` claim without verifying the signature
  (`_jwt_subject`, `stub/backend.py:128-157`) -- deliberate, per that
  function's own docstring: the stub holds no key for this hop and applies
  no issuer, audience or expiry check, because its one job is subject
  scoping, not acting as an authorization server.

The literal prefix is checked first (`stub/backend.py:189-191`), and the
code says why (`stub/backend.py:172-177`): `stub.read.cust_7f3a` is itself
three dot-separated segments, the same shape a JWT has, so a JWT-shaped
check applied first would claim it and then fail to base64-decode `read` as
a claims payload. `tests/test_stub_subject_scoping.py:251-257`
(`test_a_stub_token_is_not_mistaken_for_a_jwt`) pins exactly this ordering.

Once a subject is resolved, each route filters the fixture rows through
`OWNERS`, a fixture-id-to-customer map (`stub/backend.py:90-94`): `accounts`,
`cards` and `transactions` return only the rows their owner matches;
`balance` answers 404, not 403, for an account that exists but belongs to
someone else, on the stated reasoning that a 403 would confirm the account's
existence to a caller who does not own it, functioning as an enumeration
oracle (`stub/backend.py:213-221`). That is a narrower response than the
zero-trust plan's own acceptance wording for the real services asks for --
"a token for customer A requesting customer B's account returns 403, not
200" (`docs/bank-mcp-zero-trust-plan.md:108`) -- but that acceptance
criterion gates the bank's real domain services in their own CI
(`docs/bank-mcp-zero-trust-plan.md:110`), not this stub, so this record
notes the difference without treating it as a discrepancy to fix here.

## The control was shown to be a control, by its author, not re-measured here

Commit `316b51c`'s own message states the regression check: "`86` tests;
`83` of them fail against the previous stub, measured by restoring it and
rerunning." That is the commit author's measurement, attributed to them
here rather than claimed as this record's own. It was not reproduced in
this session: reproducing it means checking out the pre-`316b51c` version of
`stub/backend.py`, and this session was told not to touch that file, which
another session in the main checkout currently owns.

What this session did verify directly, against the current code: running
`uv run pytest tests/test_stub_subject_scoping.py -q` today returns `86
passed`, matching the commit message's stated test count. Running `make ci`
today returns `762 passed`, exit 0, with no skips (Docker was reachable).
Neither number reproduces the 83-of-86 regression; both confirm the current
state is what the commit says it left behind, not what it says it replaced.

## The gap: exactly one test file reaches the stub

`tests/test_stub_subject_scoping.py:31` is the only line in `tests/`,
`services/` or `packages/` that imports `stub.backend`
(`from stub import backend as stub`; confirmed by grepping all three
directories for `stub.backend`, `stub/backend.py`, `from stub` and
`import stub`).

The two files most likely to have needed it do not:

- `tests/test_masking_golden.py:65-75` defines its own `_handler`, closed
  over a `ROUTES` dict built from `tests/fixtures/backend_responses.py` --
  a second module that carries the same PAN, IBAN and account/card values
  `stub/backend.py` does, maintained independently of it. That handler
  answers every path with the same fixture body regardless of caller,
  passed to `httpx2.MockTransport(_handler)`; it never constructs or
  imports `stub.app`.
- `tests/test_consent_enforcement.py:122-123` defines a module-level
  `backend()` function that returns `{"cards": [], "accounts": [],
  "transactions": []}` for every path, also passed to
  `httpx2.MockTransport`. It never imports the stub either.

Every other hit for the word "stub" in `tests/` is unrelated to
`stub/backend.py`: `StubTokenMinter` usage and assertions in
`test_facade_client.py` and `test_asgi_app.py`, `allow_stub_token_minter=True`
settings flags in `test_asgi_app.py` and `test_consent_enforcement.py`, and
comments about typeshed/mypy stubs in `test_customer_ref_width.py` and
`test_store_models.py`. None of these reach `stub/backend.py`, directly or
through another module.

So the compose stack, driven by hand or by a script, can now be made to fail
a cross-customer request. The pytest suite's masking and consent coverage
still cannot: both run against fixture data that answers every caller the
same way, the same property the stub itself had before `316b51c`.

## What this means for the four existing `docs/verification/` records

All four records under `docs/verification/` predate commit `316b51c`
(2026-09-16T20:37:37+02:00):

| Record | Commit | Timestamp | Names the authorization gap itself? |
|---|---|---|---|
| `2026-09-14-stack-run.md` | `790ab94` | 2026-09-14T19:08:31+02:00 | No |
| `2026-09-16-consent-and-audit.md` | `2011250` | 2026-09-16T09:35:05+02:00 | No |
| `2026-09-16-audit-arguments-redaction.md` | `5facfd0` | 2026-09-16T13:54:49+02:00 | Yes (lines 326-337) |
| `2026-09-16-redaction-budget-exhausted.md` | `b3f6264` | 2026-09-16T15:32:21+02:00 | Yes (lines 463-479) |

Every one of the four ran against a stub that could not fail a
cross-customer request, regardless of what else it proved, because the
stub did not read the request. Two of the four already say so, in their own
"What was not, and could not be, verified this way" sections, with the same
`acc_4111111111114417` example this record cites above. The other two --
`2026-09-14-stack-run.md` and `2026-09-16-consent-and-audit.md` -- do not
mention authorization, cross-customer access or ZT-2 anywhere in their own
gap sections; their claims (device/IdP wiring, cache headers, consent
filtering and audit rows) stand as written, and none of them was about
authorization to begin with, but a reader treating either as having
exercised it would be wrong. None of the four is edited by this record: a
dated verification record is a claim about what was observed at the time,
and none of the four claimed to have exercised authorization.

## What closing the remaining gap would cost, if someone decides to

Not recommended here, only described. Pointing
`tests/test_masking_golden.py` and `tests/test_consent_enforcement.py` at
`stub.app` (via `httpx2.ASGITransport(app=stub.app)` in place of their own
handlers) would, mechanically, still pass today's cases:
`test_masking_golden.py`'s `CASES` dict only ever names `acc_7f3a` and
`crd_1`, both owned by `cust_7f3a` in `stub.OWNERS`, and its `server`
fixture always resolves the customer to `cust_7f3a`
(`tests/conftest.py`'s `TEST_CUSTOMER`), so no case would newly 401 or come
back empty.

Two costs are not mechanical, though. First, `tests/fixtures/backend_responses.py`
would become a second, separately maintained copy of data `stub/backend.py`
already carries, the exact duplication `stub/backend.py`'s own comment
(lines 76-89) discusses -- there, the reasoning goes the other way (keeping
`OWNERS` off the golden fixture so a forgotten strip cannot leak a
customer ref), but the underlying tension, two editable copies of the same
values needing to agree, is the same one. Second,
`test_consent_enforcement.py`'s `backend()` handler is deliberately
domain-agnostic today -- one empty body for every path, because that file
tests consent filtering and rejection, not fixture content. Wiring it to
the stub would make its assertions depend on `stub.OWNERS` and a
subject-matched token for the first time, coupling a consent test to an
authorization mapping it does not exercise today. Whether that coupling is
worth the coverage is not this record's call.

## What was not, and could not be, verified this way

- [ ] **ZT-2 itself.** The bank's real domain services are not in this
  repository. Nothing here states or implies anything about whether they
  enforce on `sub`.
- [ ] **The 83-of-86 regression measurement.** Attributed to commit
  `316b51c`'s own message, not reproduced in this session, because
  reproducing it means restoring the pre-fix `stub/backend.py`, a file
  another concurrent session owns in the main checkout.
- [ ] **Whether rewiring `test_masking_golden.py` and
  `test_consent_enforcement.py` onto the stub is worth the coupling
  described above.** Left open; no code was changed to test it either way.
- [ ] **Whether the stub's 404-not-403 choice on a foreign account
  (`stub/backend.py:213-221`) is the right answer for the real services'
  ZT-2 acceptance criterion** ("returns 403, not 200",
  `docs/bank-mcp-zero-trust-plan.md:108`). That criterion gates the bank's
  own services in their own CI, not this stub; this record only notes the
  stub took a different status code, for a stated reason, and does not
  extend that choice into a recommendation for the real services.

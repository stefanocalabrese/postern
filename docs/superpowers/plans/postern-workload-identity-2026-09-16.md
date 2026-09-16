# Postern Workload Identity Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make "the tool handler cannot reach a backend write endpoint" an infrastructure property rather than a code-review promise, by giving the read and write paths separate signing keys, separate issuers and separate JWKS endpoints.

**Architecture:** A `KeySource` seam supplies a signing key and its public JWKS; a pure `InternalTokenMinter` turns a key plus claims into an RFC 8693 delegation token with a 60 second life. `services/api` constructs only a read minter and publishes only the read JWKS; `services/confirm` gains a real composition root that constructs only a write minter and publishes only the write JWKS. Vault never appears in a signature any test touches.

**Tech Stack:** joserfc 1.7.5 (already installed, currently undeclared), Starlette routing, on the existing FastMCP 4.0.3 / Python 3.12 stack.

---

## Scope and boundaries

**In scope:** the `KeySource` seam with a file-backed and a generated implementation, `InternalTokenMinter`, widening `TokenMinter` to carry the claims §7.2 requires, two JWKS endpoints, a minimal `services/confirm` composition root, and tests that make the split a property.

**Out of scope, deliberately:**

| Deferred | Why |
|---|---|
| Vault itself: `hvac`, AWS IAM auth, lease renewal | Handoff §10.24 has not decided sidecar versus direct client, and §10.22 has not confirmed two Vault roles exist. `KeySource` is the seam that makes this a drop-in. |
| The approval callback and execution | Plan 5 and 6. `services/confirm` here is a composition root and a minter, nothing that moves money. |
| The IAM policy test (zero-trust plan gate 5) | Asserts the read task role cannot assume the write role. Lives in the Terraform repo, not expressible here. |
| Key rotation overlap | Needs the real Vault rotation contract. The `KeySet` mechanics are verified below so the later task is mechanical. |
| `challenge_id` on write tokens | There are no challenges until Plan 5. The claim is supported by the minter and unused. |

## Verified facts this plan depends on

Measured on 2026-09-16 against the installed packages and a real Postgres. Anything not here is design reasoning.

**The finding that shapes the whole plan.** The handoff says "publish **a** JWKS at a stable URL". A single shared key set voids the key split:

```
read key, claims iss=mcp-write, verified against a COMBINED jwks   -> ACCEPTED, split defeated
read key, claims iss=mcp-write, verified against a WRITE-ONLY jwks -> REJECTED, InvalidKeyIdError
```

A compromised API process holding only the read key mints a token claiming the write issuer, signs it with the read key, and a gateway resolving that issuer against a combined key set accepts it. **Two issuers require two disjoint key sets.** Whether an Istio `RequestAuthentication` can bind each issuer to its own key set within one `jwksUri` is NOT VERIFIED and is the platform team's answer; until it is, each service publishes only its own key.

**joserfc 1.7.5:**
- Already installed, pinned at `uv.lock:983`, pulled transitively by `fastmcp-slim[server]` and `Authlib`. **Not declared in any `pyproject.toml`**, and `stub/backend.py:18` already imports it that way. This plan declares it.
- `jwt.encode(header, claims, key)`, header first. `typ: JWT` is injected automatically.
- `KeySet.as_dict()` defaults to public-only; `d, p, q, dp, dq, qi` appear only under `private=True`. A substring check for `'"d"'` is useless because `"read-1"` contains a `d`; assert on the key set of each entry.
- `KeySet` selects by `kid` on verification and raises `InvalidKeyIdError` when absent. It does NOT reject duplicate `kid`s.
- **`kid` is read-only, there is no setter.** A bare PEM import yields `kid = None`, unrecoverable afterwards. The `kid` must be supplied at import through `parameters={"kid": ...}` or derived from `thumbprint()`.
- **`jwt.decode` verifies the signature only and does NOT validate claims.** An expired token decodes without error. `exp` and `nbf` are enforced only by `JWTClaimsRegistry`, only if present; a token with no `exp` passes. `iss` and `aud` are never checked unless declared as registry options.
- **`act.sub` cannot be validated by the registry**: dotted keys are unsupported and raise `MissingClaimError`. The RFC 8693 actor check must be hand-written.
- `essential` keys are checked before value checks, so one missing essential claim masks every other error. Use one narrow registry per assertion.

**Serving JWKS:** appending a `Route` to the object `create_app` returns works, serves anonymously while `/mcp` still 401s, and leaves the lifespan wrapper untouched. Mounting under a parent also works but reads `StarletteWithLifespan.lifespan`, which is a property returning `self.router.lifespan_context` at construction time; it is safe today only because `create_app` applies the wrapper before returning, and anyone who later reorders that silently loses `backend.aclose()` and `db.close()` **with no error and no failing test**. Measured. Use the append.

**`HeaderBodyValidation` does not interfere:** it short-circuits on `scope["method"] != "POST"`, so a GET is never inspected on any path at any strictness.

**The import-linter contract is live but currently vacuous:** `services/confirm/__init__.py` is 0 bytes, so "must not import the write path" is trivially satisfied. Proven to bite when given a real target (`BROKEN`, exit 1).

**Vault, for whenever it lands:** `hvac` 2.4.0 is sync-only with no async adapter, has no credential provider chain (Fargate task-role credentials come from `$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI` and something must fetch them), and hardcodes `https://sts.amazonaws.com/` inside the signature so a regional or VPC-endpoint STS is not expressible through `iam_login`. The handoff's preferred answer, a Vault Agent sidecar, removes all three problems and the `hvac` dependency with them.

## Design decisions this plan locks in

**D1. Two JWKS endpoints, never one combined.** `services/api` publishes the read key only; `services/confirm` publishes the write key only. Forced by the measurement above. If the platform team later confirms Istio can partition one `jwksUri` by issuer, that is a simplification to revisit with evidence, not an assumption to start from.

**D2. The seam is `KeySource`, not a Vault client.** `KeySource` supplies a signing key and its public JWKS. Vault's auth handshake, leases and TTLs live behind it and never appear in a signature a test touches. Wrapping `hvac.Client` in a Protocol would just rename hvac's API.

**D3. The JWKS route is appended to the app `create_app` returns.** Not mounted under a parent, for the lifespan-ordering hazard above.

**D4. Tests validate claims explicitly.** Because `jwt.decode` checks only the signature, every test asserting a token is rejected must declare the registry options it relies on, or it asserts nothing. The `act.sub` check is hand-written.

**D5. `services/confirm` gains real content so the import-linter contract stops being vacuous.** The write minter's construction lives there, which finally gives the contract a target worth forbidding.

## File structure

```
packages/postern-core/src/postern_core/auth/
  keys.py          # KeySource protocol, GeneratedKeySource, FileKeySource
  internal_jwt.py  # InternalTokenMinter, pure, no I/O
services/api/
  jwks.py          # the read JWKS route handler
services/confirm/
  settings.py      # write key path and issuer, NO read key field
  minter.py        # constructs the write minter, the module api must never import
  main.py          # minimal composition root publishing the write JWKS
tests/
  test_internal_jwt.py
  test_key_sources.py
  test_jwks_endpoints.py
  test_key_split_is_a_property.py
```

---

### Task 0: Declare joserfc and build the KeySource seam

**Files:**
- Modify: `packages/postern-core/pyproject.toml`
- Create: `packages/postern-core/src/postern_core/auth/__init__.py`, `packages/postern-core/src/postern_core/auth/keys.py`
- Test: `tests/test_key_sources.py`

`joserfc` is already installed at 1.7.5, pulled transitively by `fastmcp-slim[server]` and `Authlib`, and `stub/backend.py:18` already imports it. Riding a transitive is how a dependency disappears in a future upgrade of something unrelated, so declare it.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_key_sources.py
import json
from pathlib import Path

import pytest
from joserfc.jwk import RSAKey

from postern_core.auth.keys import FileKeySource, GeneratedKeySource

_PRIVATE_PARAMS = {"d", "p", "q", "dp", "dq", "qi"}


def test_generated_source_yields_a_signing_key_with_the_given_kid() -> None:
    src = GeneratedKeySource(kid="read-1")
    assert src.signing_key().kid == "read-1"
    assert src.signing_key().is_private is True


def test_generated_source_is_stable_across_calls() -> None:
    """A minter calls signing_key() per token; a fresh key each time would
    rotate mid-flight and break every token already in the air."""
    src = GeneratedKeySource(kid="read-1")
    assert src.signing_key() is src.signing_key()


def test_public_jwks_contains_no_private_material() -> None:
    src = GeneratedKeySource(kid="read-1")
    doc = src.public_jwks()
    assert set(doc) == {"keys"}
    for entry in doc["keys"]:
        assert set(entry) & _PRIVATE_PARAMS == set(), entry
        assert entry["kid"] == "read-1"


def test_public_jwks_is_json_serialisable() -> None:
    json.dumps(GeneratedKeySource(kid="read-1").public_jwks())


def test_file_source_loads_a_pem_and_applies_the_kid(tmp_path: Path) -> None:
    """joserfc's kid is read-only with no setter, so a bare PEM import yields
    kid=None and it can never be recovered. It must be supplied at import."""
    pem = RSAKey.generate_key(2048).as_pem(private=True)
    path = tmp_path / "read.pem"
    path.write_bytes(pem)
    src = FileKeySource(path, kid="read-1")
    assert src.signing_key().kid == "read-1"
    assert set(src.public_jwks()["keys"][0]) & _PRIVATE_PARAMS == set()


def test_file_source_fails_loudly_on_a_missing_file(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        FileKeySource(tmp_path / "absent.pem", kid="read-1")


def test_two_sources_produce_disjoint_key_sets() -> None:
    """The whole key split rests on this."""
    read = GeneratedKeySource(kid="read-1")
    write = GeneratedKeySource(kid="write-1")
    read_kids = {e["kid"] for e in read.public_jwks()["keys"]}
    write_kids = {e["kid"] for e in write.public_jwks()["keys"]}
    assert read_kids.isdisjoint(write_kids)
```

- [ ] **Step 2: Run it to verify it fails**

Run: `uv run pytest tests/test_key_sources.py -q`
Expected: FAIL, `ModuleNotFoundError: No module named 'postern_core.auth'`

- [ ] **Step 3: Declare the dependency**

In `packages/postern-core/pyproject.toml`, add to `[project].dependencies`:

```toml
    "joserfc>=1.7.5,<2",
```

Run `uv sync` and confirm `uv.lock` still resolves. It should already be present at 1.7.5; declaring it only makes the edge explicit.

- [ ] **Step 4: Write `keys.py`**

```python
# packages/postern-core/src/postern_core/auth/keys.py
"""Where a signing key comes from.

This is the seam Vault lands behind. Nothing above it knows whether the key
was generated in process, read from a file rendered by a Vault Agent sidecar,
or fetched over the API, and no test in this repo touches Vault.

joserfc's `kid` is read-only and has no setter: a bare PEM import yields
`kid=None`, which cannot be recovered afterwards, so every implementation
must supply the kid at construction.
"""

from pathlib import Path
from typing import Any, Protocol

from joserfc.jwk import KeySet, RSAKey

_PARAMS = {"use": "sig", "alg": "RS256"}


class KeySource(Protocol):
    """Supplies one signing key and the public JWKS for it."""

    def signing_key(self) -> RSAKey: ...

    def public_jwks(self) -> dict[str, Any]: ...


class GeneratedKeySource:
    """An in-process key. For tests and local development only."""

    def __init__(self, *, kid: str) -> None:
        self._key = RSAKey.generate_key(2048, parameters={"kid": kid, **_PARAMS})

    def signing_key(self) -> RSAKey:
        return self._key

    def public_jwks(self) -> dict[str, Any]:
        return KeySet([self._key]).as_dict()


class FileKeySource:
    """A PEM on disk, which is the shape a Vault Agent sidecar renders."""

    def __init__(self, path: Path, *, kid: str) -> None:
        self._key = RSAKey.import_key(path.read_bytes(), parameters={"kid": kid, **_PARAMS})

    def signing_key(self) -> RSAKey:
        return self._key

    def public_jwks(self) -> dict[str, Any]:
        return KeySet([self._key]).as_dict()
```

`KeySet.as_dict()` defaults to public-only, so the private parameters are absent by construction rather than by filtering.

- [ ] **Step 5: Run it to verify it passes**

Run: `uv run pytest tests/test_key_sources.py -q`
Expected: PASS, 7 passed

- [ ] **Step 6: Run the gates and commit**

Run: `make ci`
Expected: exit 0.

```bash
git add packages/postern-core/pyproject.toml uv.lock packages/postern-core/src/postern_core/auth tests/test_key_sources.py
git commit -m "feat(auth): KeySource seam with generated and file-backed implementations"
```

---

### Task 1: The internal token minter

**Files:**
- Create: `packages/postern-core/src/postern_core/auth/internal_jwt.py`
- Test: `tests/test_internal_jwt.py`

Handoff §7.2: RFC 8693 delegation, customer as `sub`, service as `act.sub`, 60 second expiry, no PII in claims because JWTs land in logs and traces.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_internal_jwt.py
from datetime import UTC, datetime

import pytest
from joserfc import jwt
from joserfc.errors import ExpiredTokenError, InvalidClaimError
from joserfc.jwk import KeySet

from postern_core.auth.internal_jwt import InternalTokenMinter
from postern_core.auth.keys import GeneratedKeySource
from postern_core.identity import CustomerRef

READ_ISS = "https://mcp-read.bank.internal"
CUST = CustomerRef(value="cust_7f3a")


@pytest.fixture
def minter() -> InternalTokenMinter:
    return InternalTokenMinter(issuer=READ_ISS, key_source=GeneratedKeySource(kid="read-1"))


def decode(minter: InternalTokenMinter, token: str) -> dict:
    keyset = KeySet.import_key_set(minter.key_source.public_jwks())
    return jwt.decode(token, keyset, algorithms=["RS256"]).claims


def test_the_customer_is_the_subject_and_the_service_is_the_actor(minter) -> None:
    claims = decode(minter, minter.mint(subject=CUST, audience="accounts.svc", scope="accounts:read"))
    assert claims["sub"] == "cust_7f3a"
    assert claims["act"] == {"sub": "svc:postern"}


def test_the_token_carries_the_issuer_and_audience(minter) -> None:
    claims = decode(minter, minter.mint(subject=CUST, audience="accounts.svc", scope="accounts:read"))
    assert claims["iss"] == READ_ISS
    assert claims["aud"] == "accounts.svc"


def test_the_token_expires_in_sixty_seconds(minter) -> None:
    claims = decode(minter, minter.mint(subject=CUST, audience="accounts.svc", scope="accounts:read"))
    assert claims["exp"] - claims["iat"] == 60


def test_every_token_carries_an_exp(minter) -> None:
    """joserfc enforces exp only if present: a token without one validates
    forever. Measured. So the minter must always set it."""
    claims = decode(minter, minter.mint(subject=CUST, audience="accounts.svc", scope="accounts:read"))
    assert "exp" in claims


def test_each_token_has_a_unique_jti(minter) -> None:
    a = decode(minter, minter.mint(subject=CUST, audience="accounts.svc", scope="accounts:read"))
    b = decode(minter, minter.mint(subject=CUST, audience="accounts.svc", scope="accounts:read"))
    assert a["jti"] != b["jti"]


def test_an_expired_token_is_rejected_by_a_claims_registry(minter) -> None:
    """jwt.decode checks the signature only. The registry is what enforces exp."""
    token = minter.mint(subject=CUST, audience="accounts.svc", scope="accounts:read")
    claims = decode(minter, token)
    future = datetime.fromtimestamp(claims["exp"] + 1, tz=UTC)
    with pytest.raises(ExpiredTokenError):
        jwt.JWTClaimsRegistry(now=int(future.timestamp())).validate(claims)


def test_a_wrong_issuer_is_rejected_when_the_registry_declares_it(minter) -> None:
    claims = decode(minter, minter.mint(subject=CUST, audience="accounts.svc", scope="accounts:read"))
    with pytest.raises(InvalidClaimError):
        jwt.JWTClaimsRegistry(iss={"essential": True, "value": "https://elsewhere"}).validate(claims)


def test_optional_claims_are_absent_when_not_supplied(minter) -> None:
    claims = decode(minter, minter.mint(subject=CUST, audience="accounts.svc", scope="accounts:read"))
    assert "challenge_id" not in claims


def test_a_challenge_id_is_carried_when_supplied(minter) -> None:
    claims = decode(
        minter,
        minter.mint(
            subject=CUST, audience="payments.svc", scope="payments:execute", challenge_id="chg_1"
        ),
    )
    assert claims["challenge_id"] == "chg_1"


def test_no_customer_pii_reaches_the_claims(minter) -> None:
    """JWTs land in logs and traces (handoff §7.2). `sub` is an opaque ref."""
    claims = decode(minter, minter.mint(subject=CUST, audience="accounts.svc", scope="accounts:read"))
    blob = str(claims)
    assert "ES9121000418450200051332" not in blob
    assert "4111111111114417" not in blob


def test_the_header_names_the_signing_kid(minter) -> None:
    token = minter.mint(subject=CUST, audience="accounts.svc", scope="accounts:read")
    keyset = KeySet.import_key_set(minter.key_source.public_jwks())
    assert jwt.decode(token, keyset, algorithms=["RS256"]).header["kid"] == "read-1"
```

- [ ] **Step 2: Run it to verify it fails**

Run: `uv run pytest tests/test_internal_jwt.py -q`
Expected: FAIL, `ModuleNotFoundError: No module named 'postern_core.auth.internal_jwt'`

- [ ] **Step 3: Write `internal_jwt.py`**

```python
# packages/postern-core/src/postern_core/auth/internal_jwt.py
"""Minting the token for one internal hop (handoff §7.2).

Pure: a key plus claims in, a signed string out, no I/O. Vault lives behind
`KeySource` and never appears here.

One instance per Vault role. The API service constructs the READ minter only;
the confirm service constructs the WRITE minter only. There is deliberately no
code path that gives one process both, which is what makes the separation an
infrastructure property rather than a code-review promise.
"""

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from joserfc import jwt

from postern_core.auth.keys import KeySource
from postern_core.identity import CustomerRef

_LIFETIME = timedelta(seconds=60)


@dataclass(frozen=True)
class InternalTokenMinter:
    issuer: str
    key_source: KeySource
    actor: str = "svc:postern"

    def mint(
        self,
        *,
        subject: CustomerRef,
        audience: str,
        scope: str,
        consent_id: str | None = None,
        client_id: str | None = None,
        challenge_id: str | None = None,
    ) -> str:
        now = datetime.now(UTC)
        claims: dict[str, Any] = {
            "iss": self.issuer,
            "sub": subject.value,
            "act": {"sub": self.actor},
            "aud": audience,
            "scope": scope,
            "iat": int(now.timestamp()),
            "exp": int((now + _LIFETIME).timestamp()),
            "jti": str(uuid.uuid4()),
        }
        for name, value in (
            ("consent_id", consent_id),
            ("client_id", client_id),
            ("challenge_id", challenge_id),
        ):
            if value is not None:
                claims[name] = value

        key = self.key_source.signing_key()
        return jwt.encode({"alg": "RS256", "kid": key.kid}, claims, key)
```

`exp` is always set because joserfc enforces it only when present: a token without one validates forever, measured.

- [ ] **Step 4: Run it to verify it passes**

Run: `uv run pytest tests/test_internal_jwt.py -q`
Expected: PASS, 11 passed

- [ ] **Step 5: Commit**

```bash
git add packages/postern-core/src/postern_core/auth/internal_jwt.py tests/test_internal_jwt.py
git commit -m "feat(auth): RFC 8693 internal token minter with a 60 second life"
```

---

### Task 2: The API holds the read key, and only the read key

**Files:**
- Create: `packages/postern-core/src/postern_core/auth/read_minter.py`
- Modify: `services/api/settings.py`, `services/api/main.py`
- Test: `tests/test_read_minter.py`, `tests/test_asgi_app.py`

`BackendClient` calls a `TokenMinter`, whose protocol is `__call__(customer, audience) -> str`. `InternalTokenMinter.mint` is wider. Rather than change `BackendClient`, adapt.

**On the claims that are NOT plumbed yet.** §7.2 wants `consent_id` and `client_id` on every internal token. `client_id` is reachable (`get_access_token().client_id`) but `BackendClient.get_json` has no access to it, and `consent_id` would need the tool layer to pass the row id from `consents`. Both are real plumbing through the façade signature and neither is this task. The minter supports both; this task supplies neither, and the omission is recorded in the "does not establish" table rather than hidden.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_read_minter.py
import pytest
from joserfc import jwt
from joserfc.jwk import KeySet

from postern_core.auth.internal_jwt import InternalTokenMinter
from postern_core.auth.keys import GeneratedKeySource
from postern_core.auth.read_minter import READ_SCOPES, ReadTokenMinter
from postern_core.identity import CustomerRef

CUST = CustomerRef(value="cust_7f3a")
ISS = "https://mcp-read.bank.internal"


@pytest.fixture
def source() -> GeneratedKeySource:
    return GeneratedKeySource(kid="read-1")


@pytest.fixture
def minter(source: GeneratedKeySource) -> ReadTokenMinter:
    return ReadTokenMinter(InternalTokenMinter(issuer=ISS, key_source=source))


def test_it_satisfies_the_token_minter_protocol(minter, source) -> None:
    token = minter(CUST, "accounts.svc")
    claims = jwt.decode(token, KeySet.import_key_set(source.public_jwks()), algorithms=["RS256"]).claims
    assert claims["sub"] == "cust_7f3a"
    assert claims["aud"] == "accounts.svc"


def test_the_scope_is_derived_from_the_audience(minter, source) -> None:
    token = minter(CUST, "cards.svc")
    claims = jwt.decode(token, KeySet.import_key_set(source.public_jwks()), algorithms=["RS256"]).claims
    assert claims["scope"] == "cards:read"


def test_every_derived_scope_is_a_read_scope() -> None:
    """A write scope reachable from the read minter would defeat the split
    even with the right key, because Istio matches on claims too."""
    for scope in READ_SCOPES.values():
        assert scope.endswith(":read"), scope


def test_an_unknown_audience_is_refused(minter) -> None:
    """Fail closed: an audience with no mapped read scope must not silently
    mint a token with an empty or guessed scope."""
    with pytest.raises(KeyError):
        minter(CUST, "payments.svc")


def test_the_payments_audience_is_not_mintable(minter) -> None:
    with pytest.raises(KeyError):
        minter(CUST, "payments.svc")
```

- [ ] **Step 2: Run it to verify it fails**

Run: `uv run pytest tests/test_read_minter.py -q`
Expected: FAIL, `ModuleNotFoundError: No module named 'postern_core.auth.read_minter'`

- [ ] **Step 3: Write `read_minter.py`**

```python
# packages/postern-core/src/postern_core/auth/read_minter.py
"""Adapts the internal minter to the TokenMinter protocol BackendClient calls.

Read audiences only. `payments.svc` is deliberately absent: asking this minter
for a write audience raises rather than minting a token with a guessed scope.
That is a second, independent barrier to the key split. Even holding the right
key, a write token from here would carry the wrong scope, and Istio matches on
claims as well as on the signature.
"""

from postern_core.auth.internal_jwt import InternalTokenMinter
from postern_core.identity import CustomerRef

READ_SCOPES = {
    "accounts.svc": "accounts:read",
    "transactions.svc": "transactions:read",
    "cards.svc": "cards:read",
}


class ReadTokenMinter:
    def __init__(self, minter: InternalTokenMinter) -> None:
        self._minter = minter

    def __call__(self, customer: CustomerRef, audience: str) -> str:
        scope = READ_SCOPES[audience]
        return self._minter.mint(subject=customer, audience=audience, scope=scope)
```

- [ ] **Step 4: Add the settings**

In `services/api/settings.py`, add three fields after `database_url`:

```python
    read_key_pem_path: str | None = None
    read_key_kid: str = "read-1"
    read_token_issuer: str = "https://mcp-read.bank.internal"
```

and in `from_env`:

```python
            read_key_pem_path=os.environ.get("POSTERN_READ_KEY_PEM_PATH") or None,
            read_key_kid=os.environ.get("POSTERN_READ_KEY_KID", "read-1"),
            read_token_issuer=os.environ.get(
                "POSTERN_READ_TOKEN_ISSUER", "https://mcp-read.bank.internal"
            ),
```

`read_key_pem_path` defaults to `None`, meaning generate in process, which is what local development and the tests want. Note the `or None` so an empty string behaves as absent, the same fix Plan 1's Task 13 needed for the JWKS variables.

- [ ] **Step 5: Wire it in `create_app`**

Replace the `StubTokenMinter()` construction with a read minter built from the settings: a `FileKeySource` when `read_key_pem_path` is set, otherwise a `GeneratedKeySource`. Stash the key source on `app.state.postern_read_key_source`, which Task 3's JWKS route needs.

Leave the existing production guard alone: `create_app` must still refuse to start with `StubTokenMinter` under a production-shaped configuration. Since the stub is no longer constructed here, check what that guard now tests and report it. If it has become dead code, say so rather than deleting it unasked.

- [ ] **Step 6: Run the gates and commit**

Run: `make ci`
Expected: exit 0. The existing `test_asgi_app.py` end-to-end tests must still pass; the backend stub does not verify the token, so swapping the minter changes nothing it can observe.

```bash
git add packages/postern-core/src/postern_core/auth/read_minter.py services/api/settings.py services/api/main.py tests/test_read_minter.py
git commit -m "feat(api): the API process mints with a read key and read scopes only"
```

---

### Task 3: Publish the read JWKS

**Files:**
- Create: `services/api/jwks.py`
- Modify: `services/api/main.py`
- Test: `tests/test_jwks_endpoints.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_jwks_endpoints.py
import httpx2
import pytest

from services.api.main import create_app
from services.api.settings import Settings
from tests.conftest import TEST_CUSTOMER

_PRIVATE_PARAMS = {"d", "p", "q", "dp", "dq", "qi"}


@pytest.fixture
def app():
    return create_app(Settings.for_testing(), resolver=lambda: TEST_CUSTOMER)


async def get(app, path: str, headers: dict[str, str] | None = None) -> httpx2.Response:
    async with httpx2.AsyncClient(
        transport=httpx2.ASGITransport(app=app), base_url="http://t"
    ) as c:
        async with app.router.lifespan_context(app):
            return await c.get(path, headers=headers or {})


async def test_the_read_jwks_is_served(app) -> None:
    r = await get(app, "/.well-known/jwks.json")
    assert r.status_code == 200
    assert {e["kid"] for e in r.json()["keys"]} == {"read-1"}


async def test_the_read_jwks_carries_no_private_material(app) -> None:
    for entry in (await get(app, "/.well-known/jwks.json")).json()["keys"]:
        assert set(entry) & _PRIVATE_PARAMS == set(), entry


async def test_the_read_jwks_is_anonymous(app) -> None:
    """Istio fetches this without a customer token."""
    assert (await get(app, "/.well-known/jwks.json")).status_code == 200


async def test_the_read_jwks_never_contains_a_write_key(app) -> None:
    kids = {e["kid"] for e in (await get(app, "/.well-known/jwks.json")).json()["keys"]}
    assert not any(k.startswith("write") for k in kids)


async def test_the_header_middleware_ignores_the_jwks_get(app) -> None:
    """HeaderBodyValidation short-circuits on non-POST, so a GET is never
    inspected even carrying nonsense MCP headers. Measured."""
    r = await get(app, "/.well-known/jwks.json", {"Mcp-Method": "tools/list", "Mcp-Name": "x"})
    assert r.status_code == 200
```

- [ ] **Step 2: Run it to verify it fails**

Run: `uv run pytest tests/test_jwks_endpoints.py -q`
Expected: FAIL, 404 on the route.

- [ ] **Step 3: Write `jwks.py`**

```python
# services/api/jwks.py
"""The read JWKS endpoint.

This service publishes ONLY its own key. A combined key set holding both the
read and the write key voids the key split: a process holding just the read
key can claim the write issuer, sign with the read key, and a gateway that
resolves that issuer against a combined set accepts it. Measured 2026-09-16.
"""

from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from postern_core.auth.keys import KeySource

JWKS_PATH = "/.well-known/jwks.json"


def jwks_route(source: KeySource) -> Route:
    async def handler(_: Request) -> JSONResponse:
        return JSONResponse(source.public_jwks())

    return Route(JWKS_PATH, handler, methods=["GET"])
```

- [ ] **Step 4: Append the route in `create_app`**

Append to `app.router.routes` on the object `create_app` returns, after the lifespan wrapper is applied. Do NOT mount the MCP app under a parent Starlette app: `StarletteWithLifespan.lifespan` is a property reading `self.router.lifespan_context` at construction time, so a parent built before the wrapper is applied silently loses `backend.aclose()` and `db.close()` with no error and no failing test. Measured.

- [ ] **Step 5: Run it to verify it passes**

Run: `uv run pytest tests/test_jwks_endpoints.py -q`
Expected: PASS, 5 passed

- [ ] **Step 6: Prove the lifespan still runs**

The existing `tests/test_asgi_app.py` has a test asserting both shutdown hooks fire. Run the whole file and confirm it still passes. If it does not, the route was added in a way that displaced the wrapper, which is the exact hazard above.

Run: `uv run pytest tests/test_asgi_app.py -q`
Expected: PASS, unchanged count.

- [ ] **Step 7: Commit**

```bash
git add services/api/jwks.py services/api/main.py tests/test_jwks_endpoints.py
git commit -m "feat(api): publish the read JWKS, read key only"
```

---

### Task 4: The confirm service gets a write key and its own JWKS

**Files:**
- Create: `services/confirm/settings.py`, `services/confirm/minter.py`, `services/confirm/jwks.py`, `services/confirm/main.py`
- Test: `tests/test_confirm_service.py`

This is not the approval callback, which is Plan 5. It is the minimum that makes the split real: a second process holding a different key, publishing a different key set, under a different issuer. It also gives the import-linter contract a target worth forbidding, which today it does not have, since `services/confirm/__init__.py` is 0 bytes and the contract is therefore trivially satisfied.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_confirm_service.py
import httpx2
import pytest
from joserfc import jwt
from joserfc.errors import InvalidKeyIdError
from joserfc.jwk import KeySet

from services.confirm.main import create_confirm_app
from services.confirm.minter import WRITE_SCOPES, build_write_minter
from services.confirm.settings import ConfirmSettings

_PRIVATE_PARAMS = {"d", "p", "q", "dp", "dq", "qi"}


@pytest.fixture
def settings() -> ConfirmSettings:
    return ConfirmSettings.for_testing()


async def get(app, path: str) -> httpx2.Response:
    async with httpx2.AsyncClient(
        transport=httpx2.ASGITransport(app=app), base_url="http://t"
    ) as c:
        return await c.get(path)


def test_the_write_minter_uses_the_write_issuer(settings) -> None:
    minter, source = build_write_minter(settings)
    token = minter.mint(
        subject_value="cust_7f3a", audience="payments.svc", scope="payments:execute"
    )
    claims = jwt.decode(token, KeySet.import_key_set(source.public_jwks()), algorithms=["RS256"]).claims
    assert claims["iss"] == "https://mcp-write.bank.internal"
    assert claims["aud"] == "payments.svc"


def test_every_write_scope_is_a_write_scope() -> None:
    for scope in WRITE_SCOPES.values():
        assert not scope.endswith(":read"), scope


async def test_the_write_jwks_is_served(settings) -> None:
    r = await get(create_confirm_app(settings), "/.well-known/jwks.json")
    assert r.status_code == 200
    assert {e["kid"] for e in r.json()["keys"]} == {"write-1"}


async def test_the_write_jwks_carries_no_private_material(settings) -> None:
    for entry in (await get(create_confirm_app(settings), "/.well-known/jwks.json")).json()["keys"]:
        assert set(entry) & _PRIVATE_PARAMS == set(), entry


async def test_the_write_jwks_never_contains_a_read_key(settings) -> None:
    kids = {e["kid"] for e in (await get(create_confirm_app(settings), "/.well-known/jwks.json")).json()["keys"]}
    assert not any(k.startswith("read") for k in kids)


def test_the_confirm_settings_have_no_read_key_field() -> None:
    """The asymmetry is the point and it should be greppable."""
    import dataclasses

    names = {f.name for f in dataclasses.fields(ConfirmSettings)}
    assert not any("read" in n for n in names), names


def test_a_write_token_is_rejected_by_the_read_key_set(settings) -> None:
    from postern_core.auth.keys import GeneratedKeySource

    minter, _ = build_write_minter(settings)
    token = minter.mint(
        subject_value="cust_7f3a", audience="payments.svc", scope="payments:execute"
    )
    read_only = KeySet.import_key_set(GeneratedKeySource(kid="read-1").public_jwks())
    with pytest.raises(InvalidKeyIdError):
        jwt.decode(token, read_only, algorithms=["RS256"])
```

Note `mint(subject_value=...)`: the confirm service has no `CustomerRef` to hand at this stage, so its minter takes the opaque string. Keep `InternalTokenMinter.mint` taking a `CustomerRef` and have the write wrapper construct one, so the validation still runs.

- [ ] **Step 2: Run it to verify it fails**

Run: `uv run pytest tests/test_confirm_service.py -q`
Expected: FAIL, `ModuleNotFoundError: No module named 'services.confirm.main'`

- [ ] **Step 3: Write the four modules**

`services/confirm/settings.py`, mirroring `services/api/settings.py` but with **no read key field of any kind**:

```python
# services/confirm/settings.py
"""Settings for the write path.

There is deliberately no read key field here, and no write key field in
services/api/settings.py. The asymmetry is the control, and it is greppable.
"""

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class ConfirmSettings:
    write_key_pem_path: str | None = None
    write_key_kid: str = "write-1"
    write_token_issuer: str = "https://mcp-write.bank.internal"

    @classmethod
    def from_env(cls) -> "ConfirmSettings":
        return cls(
            write_key_pem_path=os.environ.get("POSTERN_WRITE_KEY_PEM_PATH") or None,
            write_key_kid=os.environ.get("POSTERN_WRITE_KEY_KID", "write-1"),
            write_token_issuer=os.environ.get(
                "POSTERN_WRITE_TOKEN_ISSUER", "https://mcp-write.bank.internal"
            ),
        )

    @classmethod
    def for_testing(cls) -> "ConfirmSettings":
        return cls()
```

`services/confirm/minter.py` builds the write minter and a thin wrapper exposing `mint(subject_value=..., audience=..., scope=...)`, with `WRITE_SCOPES = {"payments.svc": "payments:execute", "cards.svc": "cards:write"}`. `services/confirm/jwks.py` reuses `postern_core`'s route helper. `services/confirm/main.py` builds a bare Starlette app serving only the write JWKS.

Keep the shared minting logic in `postern_core.auth`; only the construction is split. That is handoff §8.2 as written: one library, two deployables, two Vault roles.

- [ ] **Step 4: Run it to verify it passes**

Run: `uv run pytest tests/test_confirm_service.py -q`
Expected: PASS, 7 passed

- [ ] **Step 5: Confirm the import-linter contract now has a real target**

Run: `uv run lint-imports`
Expected: `Contracts: 1 kept, 0 broken.` Then prove it bites with real content behind it: add `from services.confirm.minter import build_write_minter` to the top of `services/api/server.py`, run `lint-imports`, confirm `BROKEN` and exit 1 naming the path, revert, confirm `KEPT` and exit 0. Paste both. Before this task the contract was satisfied by an empty package and could not have failed.

- [ ] **Step 6: Commit**

```bash
git add services/confirm tests/test_confirm_service.py
git commit -m "feat(confirm): write key, write issuer and a separate JWKS"
```

---

### Task 5: Make the split a property, not a promise

**Files:**
- Test: `tests/test_key_split_is_a_property.py`

This is the task the plan exists for. The design's claim is that a compromised tool handler cannot mint a token the payments service accepts, **because it does not hold the key**. A test asserting `isinstance(minter, ReadTokenMinter)` or `minter.key.kid == "read-1"` restates the implementation and is exactly the code-review promise the design says it is replacing.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_key_split_is_a_property.py
"""The key split, tested as a capability rather than as a configuration.

Each test here asks: given everything the API process can actually produce,
does a simulated Istio write endpoint accept any of it? The answer must be no,
and it must become yes the moment someone wires the write key into the API.
"""

import pytest
from joserfc import jwt
from joserfc.errors import InvalidKeyIdError
from joserfc.jwk import KeySet

from postern_core.auth.internal_jwt import InternalTokenMinter
from postern_core.auth.keys import GeneratedKeySource
from postern_core.auth.read_minter import READ_SCOPES, ReadTokenMinter
from postern_core.identity import CustomerRef
from services.confirm.minter import build_write_minter
from services.confirm.settings import ConfirmSettings

CUST = CustomerRef(value="cust_7f3a")
WRITE_ISS = "https://mcp-write.bank.internal"


def istio_write_endpoint(token: str, write_jwks: dict) -> dict:
    """What the gateway does: resolve the kid against THIS issuer's key set,
    then check the issuer claim. Both halves matter."""
    claims = jwt.decode(token, KeySet.import_key_set(write_jwks), algorithms=["RS256"]).claims
    jwt.JWTClaimsRegistry(iss={"essential": True, "value": WRITE_ISS}).validate(claims)
    return claims


@pytest.fixture
def write_jwks() -> dict:
    _, source = build_write_minter(ConfirmSettings.for_testing())
    return source.public_jwks()


@pytest.fixture
def api_minter() -> ReadTokenMinter:
    source = GeneratedKeySource(kid="read-1")
    return ReadTokenMinter(
        InternalTokenMinter(issuer="https://mcp-read.bank.internal", key_source=source)
    )


def test_no_token_the_api_can_mint_is_accepted_by_the_write_endpoint(
    api_minter, write_jwks
) -> None:
    """Exhaustive over the API's whole mintable surface, so it survives
    someone adding a tool with a new audience."""
    for audience in READ_SCOPES:
        token = api_minter(CUST, audience)
        with pytest.raises(InvalidKeyIdError):
            istio_write_endpoint(token, write_jwks)


def test_the_api_cannot_even_ask_for_a_write_audience(api_minter) -> None:
    with pytest.raises(KeyError):
        api_minter(CUST, "payments.svc")


def test_the_write_minter_is_accepted_by_the_write_endpoint(write_jwks) -> None:
    """The control test. If this fails the others prove nothing, because a
    verifier that rejects everything would pass them all."""
    minter, _ = build_write_minter(ConfirmSettings.for_testing())
    token = minter.mint(
        subject_value="cust_7f3a", audience="payments.svc", scope="payments:execute"
    )
    assert istio_write_endpoint(token, write_jwks)["aud"] == "payments.svc"


def test_miswiring_the_write_key_into_the_api_is_caught(write_jwks) -> None:
    """The regression this file exists for. Simulate the mistake: build the
    API's minter on the WRITE key source. The write endpoint then accepts it,
    so this test asserts the failure is detectable rather than silent."""
    _, write_source = build_write_minter(ConfirmSettings.for_testing())
    miswired = ReadTokenMinter(
        InternalTokenMinter(issuer=WRITE_ISS, key_source=write_source)
    )
    accepted = istio_write_endpoint(miswired(CUST, "accounts.svc"), write_jwks)
    assert accepted["iss"] == WRITE_ISS


def test_a_combined_key_set_would_defeat_the_split(api_minter, write_jwks) -> None:
    """Why there are two JWKS endpoints and not one.

    A process holding only the read key claims the write issuer and signs with
    the read key. Against a combined key set the gateway accepts it, because
    the read key is in the set that issuer resolves against. This test pins the
    reason so nobody 'simplifies' the two endpoints into one.
    """
    read_source = api_minter._minter.key_source
    liar = InternalTokenMinter(issuer=WRITE_ISS, key_source=read_source)
    token = liar.mint(subject=CUST, audience="payments.svc", scope="payments:execute")

    with pytest.raises(InvalidKeyIdError):
        istio_write_endpoint(token, write_jwks)

    combined = {"keys": write_jwks["keys"] + read_source.public_jwks()["keys"]}
    assert istio_write_endpoint(token, combined)["iss"] == WRITE_ISS
```

- [ ] **Step 2: Run it to verify it fails**

Run: `uv run pytest tests/test_key_split_is_a_property.py -q`
Expected: FAIL on the imports until Task 4 landed; if Task 4 is already merged, all five should pass. Either way, run them and paste the output.

- [ ] **Step 3: Prove each test discriminates**

For each of the five, make the smallest change that should break it and confirm it does:

- point `api_minter` at the write key source, confirm the exhaustive test fails
- add `"payments.svc": "payments:execute"` to `READ_SCOPES`, confirm the second test fails
- drop the `iss` registry check from `istio_write_endpoint`, confirm the combined-key-set test still passes but for the wrong reason, and say what that tells you about the assertion

Paste each. Restore after each one.

- [ ] **Step 4: Commit**

```bash
git add tests/test_key_split_is_a_property.py
git commit -m "test: the read/write key split as a capability, not a configuration"
```

---

### Task 6: Verify against the running stack

**Files:**
- Modify: `docker-compose.yml`
- Create: `docs/verification/<today>-key-split.md`

- [ ] **Step 1: Add the confirm service to compose**

A fourth service running `services.confirm.main:app` on its own port, with `POSTERN_WRITE_KEY_PEM_PATH` unset so it generates in process, as the api does today. Do not give the api any write variable and do not give confirm any read variable.

- [ ] **Step 2: Bring the stack up and fetch both JWKS**

```bash
docker compose up -d --build
curl -s http://localhost:8080/.well-known/jwks.json
curl -s http://localhost:8082/.well-known/jwks.json
```

Record both. The `kid` sets must be disjoint, and neither may contain `d`, `p`, `q`, `dp`, `dq` or `qi`.

- [ ] **Step 3: Confirm neither service can serve the other's key**

Assert the api's JWKS contains no `kid` beginning `write`, and the confirm service's contains no `kid` beginning `read`. Record the commands.

- [ ] **Step 4: Confirm a tool call still works end to end**

Mint a customer token from the stub, call `accounts.list`, confirm the masked IBAN comes back. The internal minter changed under it; the response must not have.

- [ ] **Step 5: Write the verification record and tear down**

Record every command and its real output, stating which checks ran over HTTP and which by reading a file. State plainly that **no Vault was involved**, that both services generated their keys in process, and that the real Vault integration is unbuilt and blocked on handoff §10.22 and §10.24. A record that reads as though Vault were exercised would be worse than no record.

- [ ] **Step 6: Commit**

```bash
git add docker-compose.yml docs/verification
git commit -m "docs: verify two disjoint key sets against the running stack"
```

---

## What this plan deliberately does not establish

| Not established | Why it matters | Lands in |
|---|---|---|
| Vault itself | No Vault client, no AWS IAM auth, no lease renewal. Keys are generated in process or read from a PEM. Blocked on handoff §10.22 (two roles?) and §10.24 (sidecar or `hvac`?) | unscheduled |
| `consent_id` and `client_id` on internal tokens | §7.2 wants both. The minter supports them; nothing supplies them, because `BackendClient.get_json` has neither in scope. Real plumbing through the façade signature | unscheduled |
| Key rotation overlap | The `KeySet` mechanics are verified (selection by `kid`, public-only export) but no rotation path exists. Needs the real Vault rotation contract | unscheduled |
| Whether Istio can bind two issuers to one `jwksUri` | If it can, the two endpoints could become one. Until measured, two is the safe shape, and a test pins why | platform team |
| Whether Vault supplies a `kid` with the key | joserfc's `kid` is read-only and a bare PEM yields `None`. Either Vault supplies it or we derive it from the thumbprint | platform team |
| The IAM policy test | The read task role must not be able to assume the write role or read its Vault path. Terraform repo | out of repo |
| That `act.sub` is enforced anywhere | joserfc's claims registry cannot validate dotted keys. Istio's `AuthorizationPolicy` is where the actor claim would actually be checked, and that config is not in this repo | platform team |

## Self-review

- **Spec coverage.** Handoff §7.2's claim shape, local signing, 60 second expiry and the two-role split are Tasks 1, 2 and 4. The JWKS publication is Tasks 3 and 4. The §8.2 "two deployables, one library" decision is honoured: shared minting in `postern_core.auth`, construction split across the services. The §12.3 IAM policy test is explicitly out of repo.
- **Placeholders.** None. Task 4's Step 3 describes three of its four modules in prose rather than code, deliberately, because they mirror files the implementer will have open; the one with real logic is given in full.
- **Type consistency.** `KeySource.signing_key() -> RSAKey` and `public_jwks() -> dict`, `InternalTokenMinter.mint(subject: CustomerRef, ...)`, `ReadTokenMinter.__call__(customer, audience)`, and `build_write_minter(settings) -> tuple[minter, KeySource]` are used identically wherever they appear.
- **Known risk.** Task 5's `test_a_combined_key_set_would_defeat_the_split` asserts a vulnerability exists rather than that it is absent. That is deliberate, and it is the same shape as the characterization test in `tests/test_masking_types.py`: if a future joserfc changes `kid` resolution so a combined set no longer accepts the lie, the test fails loudly and someone re-reads the reasoning, instead of the hazard quietly disappearing and the two-endpoint design looking arbitrary.

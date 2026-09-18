# 2026-09-18: two replicas, two key sets, one kid -- measured

This record upgrades exactly one claim in
`docs/verification/2026-09-18-key-split.md` from inferred to measured. That
record says, in its "What this is, and what it is not" section:

> In a multi-replica deployment every replica would do the same thing
> independently and publish a different key set under the same issuer; that
> specific claim is inferred from the single-instance restart result below,
> not measured against more than one running replica, because this compose
> stack never runs more than one instance of either service.

and repeats it as an open checklist item:

> - [ ] **Multi-replica behavior is inferred, not measured.** This compose
>   stack never runs more than one instance of `api` or `confirm`
>   simultaneously [...]

Two concurrent replicas of `api` and two of `confirm` were run here, and each
pair's JWKS was fetched over HTTP. The inference was right, and this record
measures it. It also measures the part the old record did not reach at all:
what the divergence costs a caller, using a real internal token captured from
one running replica and presented to the other replica's published key set.

Nothing in `docs/verification/2026-09-18-key-split.md` is edited by this
commit. Verification records are dated observations; this is a new one that
cites it.

## What this is, and what it is not

**No Vault was involved, anywhere in this session.** All four replicas
generated their RSA signing key in process
(`postern_core.auth.keys.GeneratedKeySource`). `FileKeySource` was not
constructed, no PEM was read from disk, no Vault or Vault Agent ran. That was
verified rather than assumed, in the running containers, not only in the
source (see "Setup" below): `docker compose exec -T api env | grep -E 'PEM|KID'`
and the same for `confirm` both printed nothing, so
`Settings.read_key_pem_path` and `ConfirmSettings.write_key_pem_path` both
resolved to their `None` default and both `_read_key_source` /
`_write_key_source` took the `GeneratedKeySource` branch.

**The token in section 3 is real, not synthetic.** It is the internal RS256
token that the running `api` replica A minted for its own call to the backend
stub during a successful `accounts.list` tool call, captured out of the
backend's `Authorization` header by a temporary probe. A second real token
from replica B was captured the same way. No locally generated stand-in key
was used anywhere in this record, and the fallback the task allowed for
(a synthetic RSA key labelled as such) was not needed.

**The probe was reverted and nothing from it is committed.** One line was
added to `stub/backend.py` inside `_subject`, immediately after
`header = request.headers.get("authorization")`:

```python
    print("PROBE-AUTH:", header, flush=True)  # TEMPORARY PROBE -- REVERT
```

`stub/backend.py` is bind-mounted into the `backend-stub` container
(`docker-compose.yml`'s `volumes: ./:/app`), so `docker compose restart
backend-stub` loaded it without a rebuild. It was applied twice (once per
captured token) and reverted with `git checkout -- stub/backend.py` both
times. `git status --porcelain` and `git diff` were both empty after each
revert, and again before this record was committed. The only file this commit
adds is this record. This follows the precedent
`docs/decisions/0004-base-images.md` sets for a probe edit ("The (reverted)
probe edit to `pyproject.toml` was never committed; `git status`/`git diff`
were checked clean before and after").

**Which evidence is which.** Four kinds appear below, labelled per section:
HTTP against a published port (`curl`), a direct write against Postgres
(`docker compose exec ... psql`, not HTTP), a JOSE validation run locally in
`uv run python` over bytes that were already fetched over HTTP (no new
request, no key generated), and a small number of claims read from a settings
file or a container's environment rather than requested.

Versions: Docker server 29.8.0, Docker Compose v5.5.1, `uv` 0.11.21, CPython
3.12.13, `joserfc` 1.7.5.

## Setup: four replicas, two of each service

`docker-compose.yml` publishes `api` on host port 8080 and `confirm` on 8082,
so `docker compose up --scale api=2` collides on the host port binding. No
override file was written and `docker-compose.yml` was not edited. Instead the
compose stack was brought up once, unchanged, and a second container of each
image was started with `docker run` on the network compose had already
created, with `api`'s environment copied verbatim from the compose service
block.

```bash
docker compose up -d --build
docker compose ps
```

```
NAME                          SERVICE        STATUS                   PORTS
replica-jwks-api-1            api            Up                       0.0.0.0:8080->8080/tcp
replica-jwks-backend-stub-1   backend-stub   Up                       0.0.0.0:8081->8081/tcp
replica-jwks-confirm-1        confirm        Up                       0.0.0.0:8082->8080/tcp
replica-jwks-db-1             db             Up (healthy)             0.0.0.0:5432->5432/tcp
```

```bash
docker run -d --name replica-b-api --network replica-jwks_default \
  -e POSTERN_BACKEND_BASE_URL=http://backend-stub:8081 \
  -e POSTERN_DATABASE_URL=postgresql+asyncpg://postern:postern@db:5432/postern \
  -e POSTERN_JWKS_URI=http://backend-stub:8081/.well-known/jwks.json \
  -e POSTERN_TOKEN_ISSUER=https://postern-local-dev.invalid \
  -e POSTERN_AUDIENCE=postern \
  -e POSTERN_STRICT_HEADERS=0 \
  -p 8090:8080 replica-jwks-api

docker run -d --name replica-b-confirm --network replica-jwks_default \
  -p 8092:8080 replica-jwks-confirm
```

Both replicas of a service run the same image built in the same
`docker compose up --build` (`replica-jwks-api`, `replica-jwks-confirm`), so
the divergence measured below cannot be attributed to two different builds.

**Environment read, not HTTP** -- the check that both services really take
the `GeneratedKeySource` branch:

```bash
docker compose exec -T api env | grep -E 'PEM|KID'
docker compose exec -T confirm env | grep -E 'PEM|KID'
docker compose exec -T api env | grep POSTERN_ | sort
```

```
(no output for either grep -E 'PEM|KID')

POSTERN_AUDIENCE=postern
POSTERN_BACKEND_BASE_URL=http://backend-stub:8081
POSTERN_DATABASE_URL=postgresql+asyncpg://postern:postern@db:5432/postern
POSTERN_JWKS_URI=http://backend-stub:8081/.well-known/jwks.json
POSTERN_STRICT_HEADERS=0
POSTERN_TOKEN_ISSUER=https://postern-local-dev.invalid
```

`docker compose exec -T confirm env | grep POSTERN_` printed nothing at all:
the `confirm` service block sets no environment. Neither
`POSTERN_READ_KEY_PEM_PATH` nor `POSTERN_WRITE_KEY_PEM_PATH` is set on any of
the four containers, so `Settings.read_key_pem_path` and
`ConfirmSettings.write_key_pem_path` are `None`
(`services/api/settings.py:19`, `services/confirm/settings.py:13`) and both
composition roots reach `GeneratedKeySource`
(`services/api/main.py:82-84`, `services/confirm/minter.py:51-53`). Neither
`POSTERN_READ_KEY_KID` nor `POSTERN_WRITE_KEY_KID` is set either, so the two
`kid` strings are the settings defaults `read-1` and `write-1`.

## 1. Two live replicas, same `kid`, different key -- verified over HTTP

```bash
curl -sS http://localhost:8080/.well-known/jwks.json   # api replica A
curl -sS http://localhost:8090/.well-known/jwks.json   # api replica B
curl -sS http://localhost:8082/.well-known/jwks.json   # confirm replica A
curl -sS http://localhost:8092/.well-known/jwks.json   # confirm replica B
```

All four bodies were saved and compared by a script run from a scratch
directory outside the repository (not committed, nothing in the repo was
changed to run it); it reads only the four already-fetched JSON documents and
issues no request of its own:

```python
import json, pathlib
def load(n): return json.loads((S/f"{n}.json").read_text())["keys"][0]
for pair in (("api-a","api-b"), ("confirm-a","confirm-b")):
    a, b = load(pair[0]), load(pair[1])
    print("  kid A =", a["kid"], "| kid B =", b["kid"], "| kid equal:", a["kid"] == b["kid"])
    print("  e   A =", a["e"],   "| e   B =", b["e"],   "| e equal:", a["e"] == b["e"])
    print("  alg/use/kty equal:", (a["alg"],a["use"],a["kty"]) == (b["alg"],b["use"],b["kty"]))
    print("  n A prefix:", a["n"][:24], "len:", len(a["n"]))
    print("  n B prefix:", b["n"][:24], "len:", len(b["n"]))
    print("  n equal:", a["n"] == b["n"])
    print("  entry fields:", sorted(a), "| private overlap:", set(a) & {"d","p","q","dp","dq","qi"})
```

```
### api-a vs api-b
  kid A = read-1 | kid B = read-1 | kid equal: True
  e   A = AQAB | e   B = AQAB | e equal: True
  alg/use/kty equal: True
  n A prefix: wPcJ8SqOljkYU9o8pnJeUUcE len: 342
  n B prefix: 4VeKwGipbUsnqbbzavwvTOCU len: 342
  n equal: False
  entry fields: ['alg', 'e', 'kid', 'kty', 'n', 'use'] | private overlap: set()

### confirm-a vs confirm-b
  kid A = write-1 | kid B = write-1 | kid equal: True
  e   A = AQAB | e   B = AQAB | e equal: True
  alg/use/kty equal: True
  n A prefix: q5weXg2FURy7j7rY6esszV_D len: 342
  n B prefix: uq7Uevwzc1xGToofH6QK47UK len: 342
  n equal: False
  entry fields: ['alg', 'e', 'kid', 'kty', 'n', 'use'] | private overlap: set()
```

Both halves of the old record's inference hold. The `kid` is the same string
on both replicas of a service (`read-1` on 8080 and 8090, `write-1` on 8082
and 8092), because it comes from a settings default and never from the key.
The modulus `n` differs on every pair. Each `n` is 342 unpadded base64url
characters, which is 256 bytes, which is the 2048-bit modulus
`RSAKey.generate_key(2048, ...)` produces in `GeneratedKeySource.__init__`
(`packages/postern-core/src/postern_core/auth/keys.py:34`); the four values
are truncated to a 24-character prefix here rather than pasted whole, and the
prefixes are enough to see that no two are the same. The public exponent `e`
is `AQAB` (65537) everywhere, as it is for essentially every RSA key, so it
distinguishes nothing. No entry on any of the four carries `d`, `p`, `q`,
`dp`, `dq` or `qi`.

## 2. The issuer both replicas claim -- read from settings and measured in a real token

**There is no issuer in the JWKS response.** The measured field set of every
entry is exactly `['alg', 'e', 'kid', 'kty', 'n', 'use']` (section 1), and
`services/api/jwks.py` / `services/confirm/jwks.py` return
`JSONResponse(source.public_jwks())` with nothing added. A client fetching
the key set learns nothing about which issuer it belongs to from the response
body.

The issuer lives in the token. `InternalTokenMinter` writes
`settings.read_token_issuer` into `iss`
(`packages/postern-core/src/postern_core/auth/internal_jwt.py:48`), and
`Settings.from_env()` reads `POSTERN_READ_TOKEN_ISSUER` with the default
`https://mcp-read.internal`. That variable is set on neither `api` replica
(the `env` dump in "Setup" is the whole `POSTERN_` set), so both default. That
is a file-and-environment read; the measured version is section 3's two real
tokens, which both carry `"iss": "https://mcp-read.internal"`. The same
applies to `confirm`'s `https://mcp-write.internal`
(`services/confirm/settings.py:15`), except that no write token was minted in
this session, so the write issuer here is a file read only and is **not
measured**.

So the shape is: one issuer string, one `kid` string, two different keys,
two live replicas.

## 3. What the divergence costs a caller -- a real token, measured

### Getting a real token

The running server's in-process key cannot be reached with
`docker compose exec ... python -c`: that starts a new process, whose
`GeneratedKeySource` generates a different key. What can be reached is the
token the running process already minted. `api` mints a real internal token on
every backend call (`services/api/main.py:169-177`), and `stub/backend.py`'s
`_subject` reads the `Authorization` header at line 182, so a probe there
captures it.

Preparation, matching section 5 of `docs/verification/2026-09-18-key-split.md`:
migrations applied from the host, and consent seeded **by a direct database
write, not over HTTP**, because `accounts.list` is gated by
`services/api/consent.consent_for` and nothing mints a consent row another
way.

```bash
POSTERN_DATABASE_URL=postgresql+asyncpg://postern:postern@localhost:5432/postern uv run alembic upgrade head
docker compose exec -T db psql -U postern -d postern -c \
  "INSERT INTO consents (customer_ref, domain, granted, granted_at, expires_at) VALUES ('cust_7f3a','accounts',true,now(),null);"
```

```
INFO  [alembic.runtime.migration] Running upgrade  -> f69be5a09d99, consents and audit log
... (six migrations, same chain as the 2026-09-18 key-split record)
INSERT 0 1
```

Probe applied, `backend-stub` restarted, then a real tool call over HTTP
against replica A on port 8080:

```bash
TOKEN=$(curl -sS "http://localhost:8081/mint-token?sub=cust_7f3a")
curl -sS http://localhost:8080/mcp \
  -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
  -H 'MCP-Protocol-Version: 2026-07-28' -H 'Mcp-Method: tools/call' -H 'Mcp-Name: accounts.list' \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"accounts.list","arguments":{},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}'
```

```json
{"jsonrpc":"2.0","id":1,"result":{"content":[{"text":"[{\"ref\":\"acc_7f3a\",\"label\":\"Joint expenses\",\"iban\":\"ES•• •••• 1332\"}]","type":"text"}],"isError":false,"resultType":"complete", ...}}
```

```bash
docker compose logs backend-stub --no-log-prefix | grep 'PROBE-AUTH' | tail -1
```

```
PROBE-AUTH: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6InJlYWQtMSJ9.eyJpc3MiOiJodHRwczovL21jcC1yZWFkLmludGVybmFs...
```

The same three commands were repeated against replica B on port 8090 to
capture a second real token. Both tokens are 674 characters. Their decoded
contents:

```
token minted by replica A: kid='read-1' iss='https://mcp-read.internal' aud='accounts.svc' jti=c48f9f19-28b4-413f-8e39-1db7ef7dd788
token minted by replica B: kid='read-1' iss='https://mcp-read.internal' aud='accounts.svc' jti=d3baf5fe-c111-4318-8a4e-5a8885fccfb9
issuers equal across replicas: True
tokens byte-identical: False
```

Replica A's full header and claims, for the record:

```
header: {'typ': 'JWT', 'alg': 'RS256', 'kid': 'read-1'}
claims: {"act": {"sub": "svc:postern"}, "aud": "accounts.svc", "exp": 1789726959,
         "iat": 1789726899, "iss": "https://mcp-read.internal",
         "jti": "c48f9f19-28b4-413f-8e39-1db7ef7dd788", "scope": "accounts:read",
         "sub": "cust_7f3a"}
```

### The 2x2: each token against each replica's published key set

Validation is `joserfc.jwt.decode(token, KeySet.import_key_set(jwks),
algorithms=["RS256"])`, which is the same call
`tests/test_key_split_is_a_property.py::istio_write_endpoint` makes to stand
in for a gateway. It ran locally over the four already-captured byte strings
(two tokens, two JWKS documents fetched in section 1); no new HTTP request was
issued and no key was generated.

```
token A -> replica A JWKS: accepted
token A -> replica B JWKS: BadSignatureError 'bad_signature: '
token B -> replica A JWKS: BadSignatureError 'bad_signature: '
token B -> replica B JWKS: accepted
```

The two accepted cases are the positive control: the token does verify, so
the two rejections are not an artefact of a mangled capture or a wrong
`algorithms` list.

### The exact failure

```
RESULT: raised joserfc.errors.BadSignatureError
repr: BadSignatureError('bad_signature: ')
str : bad_signature: 
mro : ['BadSignatureError', 'JoseError', 'Exception', 'BaseException', 'object']
```

The `kid` lookup **succeeds**. Replica B's key set publishes `read-1`, the
token's header names `read-1`, so `joserfc` resolves a key and proceeds to the
signature check, which fails. The message is `bad_signature: ` -- the prefix,
a colon, a space, and an empty description. It names no `kid`, no issuer, no
key set, no replica, and no URL. There is nothing in it that points at
configuration.

**This is the operational cost, and it is why this record exists.** A token
signed by replica A and presented to a validator holding replica B's key set
does not fail in a way that reads as drift between two instances of the same
deployment. It fails in exactly the way a token signed by an attacker's key
under a copied `kid` would fail: correct issuer, correct audience, correct
scope, correct `act.sub`, resolvable `kid`, bad signature. An operator reading
`bad_signature: ` in a gateway log has no way to distinguish "my second
replica generated its own key" from "someone forged a token", and the shape
of the evidence argues for the second reading. (That an operator *would* read
it that way is a judgement about how the message reads, not something measured
here; the message text itself is measured.)

## 4. The contrast: a genuine `kid` mismatch fails differently

Replica A's read token was presented to the `confirm` service's published key
set (port 8082, `kid` `write-1`), which is a real key set fetched over HTTP in
section 1, not a constructed one:

```
--- C: confirm replica A's JWKS (port 8082), kid write-1, genuine kid mismatch
   key set kids: ['write-1']
   RESULT: raised joserfc.errors.InvalidKeyIdError
   repr: InvalidKeyIdError("invalid_key_id: No key for kid: 'read-1'")
   str : invalid_key_id: No key for kid: 'read-1'
   mro : ['InvalidKeyIdError', 'JoseError', 'Exception', 'BaseException', 'object']
```

So the labels are confirmed rather than assumed: `InvalidKeyIdError` is the
`kid`-mismatch failure and `BadSignatureError` is the same-`kid`,
different-key failure. Both are direct subclasses of `JoseError` and neither
is a subclass of the other, so the two are distinguishable in an `except`
clause -- which `tests/test_key_split_is_a_property.py` already relies on.

The diagnostic difference between the two messages is the whole point.
`invalid_key_id: No key for kid: 'read-1'` names the key it looked for and
says it is absent, which is a configuration statement an operator can act on.
`bad_signature: ` says nothing at all. The failure mode that carries the
useful message is the one that cannot happen between two replicas of the same
service, because both replicas publish the same `kid` by construction.

## 5. One replica restarted -- consistent with the single-instance result

Section 4 of `docs/verification/2026-09-18-key-split.md` measured a
single-instance restart changing the key under an unchanged `kid`. The check
here is whether the two-replica setup agrees with it, not a re-run of it.

```bash
docker restart replica-b-api
curl -sS http://localhost:8090/.well-known/jwks.json   # replica B, after restart
curl -sS http://localhost:8080/.well-known/jwks.json   # replica A, untouched
```

```
api-b (before restart): kid=read-1 n[:16]=4VeKwGipbUsnqbbz
api-b (after restart):  kid=read-1 n[:16]=rUW8rgAV-XYlRAoI
api-a (before):         kid=read-1 n[:16]=wPcJ8SqOljkYU9o8
api-a (after):          kid=read-1 n[:16]=wPcJ8SqOljkYU9o8
api-a unchanged across replica B's restart: True
api-b changed across its own restart: True
token B -> replica B's restarted JWKS: BadSignatureError 'bad_signature: '
```

Three distinct 2048-bit keys have now been published under the single `kid`
`read-1` by the same image in one session. Restarting one replica changes only
that replica's key and leaves the other's byte-identical, which is what
"generated independently per process" predicts. The last line is the sharpest
form of the cost: the token replica B minted about two minutes earlier no
longer verifies against replica B's **own** published key set, and it fails
with the same empty `bad_signature: `.

## No defect found

Nothing behaved differently from what `services/api/main.py:66-84`,
`services/confirm/minter.py:43-53` and
`packages/postern-core/src/postern_core/auth/keys.py:30-40` already describe.
The per-process key generation is the documented behavior of an unset PEM
path; this record measures what it produces when more than one process runs,
which no record in this directory had done. No application code was changed,
and the only repository edit made to take a measurement was the one-line
probe in `stub/backend.py`, reverted (see "What this is, and what it is not").

## What was not, and could not be, verified this way

- [ ] **No Vault, no `FileKeySource`, no rendered PEM.** Unchanged from
  `docs/verification/2026-09-18-key-split.md`. Nothing here says whether a
  Vault Agent sidecar rendering the same PEM into both replicas would make
  the two key sets agree; that is the obvious fix and it is **inferred, not
  measured** -- both replicas would call `FileKeySource` on the same bytes,
  but no run in this session constructed a `FileKeySource` at all.
- [ ] **No Istio, no `RequestAuthentication`, no gateway of any kind.** The
  validator in sections 3 and 4 is `joserfc.jwt.decode` over a `KeySet`, run
  in a local Python process. Whether Istio surfaces a comparable error, what
  text it logs, and what status code it returns to the caller are all
  **unmeasured**. The claim that a gateway would behave this way rests on it
  doing the same `kid`-then-signature resolution, which is **inferred, not
  measured**.
- [ ] **`docker compose up --scale` was not used.** The second replica of each
  service is a separate `docker run` from the same image on the same compose
  network, because `docker-compose.yml`'s host port bindings (8080, 8082)
  collide under `--scale`. Whether `--scale` produces the same result is
  **inferred, not measured** -- the image and environment are identical, but
  that path was not run.
- [ ] **Two replicas, not N.** Each pair was two containers. Nothing here
  measures three or more, and nothing measures a load balancer distributing
  requests across them: both replicas were addressed directly by host port.
- [ ] **No write token was minted.** `services/confirm` publishes a JWKS and
  holds a `WriteTokenMinter`, but has no route that mints
  (`services/confirm/main.py` builds a `Starlette` with exactly one route).
  The `confirm` half of section 1 is therefore JWKS divergence only; the write
  issuer `https://mcp-write.internal` is a file read
  (`services/confirm/settings.py:15`), and no write token was presented to any
  key set here.
- [ ] **How long a cached key set stays wrong is not measured.** A gateway
  that caches a JWKS and refetches on an unknown `kid` never refetches here,
  because the `kid` is always known. That is a consequence of the same-`kid`
  finding rather than a separate observation, and no caching gateway ran in
  this session.
- [ ] **The operator-experience claim in section 3 is a judgement, not a
  measurement.** `bad_signature: ` is measured. That a human reading it
  reaches for "forged token" before "replica drift" is an argument from what
  the message does and does not contain, and no operator was observed.

## Teardown

```bash
docker rm -f replica-b-api replica-b-confirm
docker compose down -v
docker compose ps
docker ps
docker network ls | grep replica
lsof -nP -iTCP:8080 -iTCP:8081 -iTCP:8082 -iTCP:8090 -iTCP:8092 -iTCP:5432 -sTCP:LISTEN
```

```
replica-b-api
replica-b-confirm
Container replica-jwks-confirm-1 Removed
Container replica-jwks-api-1 Removed
Container replica-jwks-db-1 Removed
Container replica-jwks-backend-stub-1 Removed
Network replica-jwks_default Removed
```

`docker compose ps` returned an empty table, `docker ps` returned no rows, no
network matching `replica` remained, and all six ports were free. `docker ps`
before this session started was also empty. Two containers not created here
(`testcontainers/ryuk` and a `postgres:17-alpine` on an ephemeral high port)
appeared and disappeared during the session; they belong to another worktree's
`make ci` run and were left alone.

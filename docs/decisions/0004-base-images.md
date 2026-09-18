# 0004: Base images, and what Task 13 found wrong in its own plan

**Date:** 2026-09-14

## Digests

Resolved on 2026-09-14 with `docker buildx imagetools inspect <image> --format '{{.Manifest.Digest}}'` (Docker 29.7.2, Compose v5.5.1). Both are multi-arch manifest-list digests; each was confirmed (via the same `imagetools inspect` output, `Platform:` lines) to include a `linux/arm64` (`arm64/v8`) entry before being pinned into the `Dockerfile`:

| Image | Tag resolved from | Digest |
|---|---|---|
| `ghcr.io/astral-sh/uv:python3.12-bookworm-slim` | builder stage | `sha256:e5b65587bce7de595f299855d7385fe7fca39b8a74baa261ba1b7147afa78e58` |
| `python:3.12-slim` | runtime stage | `sha256:78387bc3881b8273120a12ebe6c1ab22b018ccc2c9adf565ae1ac9b536e184ea` |

`python:3.12-slim`, not distroless, per handoff §12.2's own recommendation for non-production (distroless has no shell, which breaks `ecs execute-command`; this stack has no ECS anywhere in it, but there is no reason to diverge from the documented non-prod choice for a local dev image).

## Build, for real

`docker build --target api --platform linux/arm64 -t postern-api:dev .` and the equivalent for `--target confirm` both succeed. Neither built on the first attempt with the plan's own Dockerfile draft:

**Finding 1 -- `--no-install-project` still tries to build the workspace member.** The plan's first `RUN uv sync --frozen --no-dev --no-install-project` (after copying only `pyproject.toml`, `uv.lock` and `packages/postern-core/pyproject.toml`, not its `src/`) failed:

```
Building postern-core @ file:///app/packages/postern-core
  Expected a Python module at:
  packages/postern-core/src/postern_core/__init__.py
```

`--no-install-project` only skips installing the *root* project; a workspace member (`postern-core`) is still built from source even though only its `pyproject.toml` has been copied at that point. `uv sync --help` (run against the actual `ghcr.io/astral-sh/uv` image) has a separate `--no-install-workspace` flag that defers every workspace member too, not just the root -- that is what the first layer now uses, keeping it cacheable across source-only changes the way the plan intended.

**Finding 2 -- `PYTHONPATH` needed setting explicitly.** `services` is not an installed package (root `pyproject.toml` sets `package = false`; only `packages/postern-core` is a workspace member `uv sync` installs into the venv). `uvicorn services.api.main:app`, run as the venv's own console-script, does not put `/app` on `sys.path` by default the way `python -m` would. `ENV PYTHONPATH="/app"` in the runtime stage is what makes `import services.api.main` resolve; without it, `uvicorn` fails to import the app at container start. Confirmed by testing the built image directly (`docker run ... python -c "import services.api.main"`).

Build output tail (api target, from a clean `--no-cache` run):

```
#14 [builder 7/7] RUN uv sync --frozen --no-dev
#14 0.138    Building postern-core @ file:///app/packages/postern-core
#14 0.140       Built postern-core @ file:///app/packages/postern-core
#14 0.144  + postern-core==0.1.0 (from file:///app/packages/postern-core)
#16 exporting to image
#16 naming to docker.io/library/postern-api:dev done
```

## The `confirm` target's expected failure

`services/confirm/main.py` does not exist in this plan (confirmed: the only file under `services/confirm/` is `__init__.py`). Running the built `confirm` image fails immediately, before binding a port, with `uvicorn`'s own import error, on `docker run`'s standard streams, exit code 3:

```
ERROR:    Error loading ASGI app. Could not import module "services.confirm.main".
```

This is already an immediate, self-explaining failure -- uvicorn's own error names the missing module and exits fast rather than hanging or half-starting -- so no placeholder module or extra handling was added. Recorded here, as the plan's own Task 13 asked, so nobody mistakes it for a build defect: it is the intended state until Plan 3 adds `services/confirm/main.py`.

## Two things the plan's compose environment got wrong

The plan's Task 13 text predates Tasks 4 and 12. Both gaps below were verified by actually running the container, not inferred from reading the code.

**1. `POSTERN_JWKS_URI: ""` / `POSTERN_TOKEN_ISSUER: ""` did not mean "no auth".** `Settings.from_env()` read both via a required `os.environ[...]`, which can only ever produce a `str` (even `""`) or a startup `KeyError` -- never `None`. `services/api/server.py::build_server` and `services/api/main.py::_refuse_stub_minter_in_production` both branch on `customer_jwks_uri is None` / `customer_token_issuer is None` to reach the no-auth path that `Settings.for_testing()` (and, per its own test's docstring, "the local docker-compose stack") rely on. Setting both to `""` in compose still creates the environment variable (compose does not omit a key set to an empty string), so `from_env()` produced two non-`None` empty strings: `build_server` treated that as "both set" and tried to construct `JWTVerifier(jwks_uri="", issuer="", ...)`, and `_refuse_stub_minter_in_production` treated it as "production-shaped" and refused to start `StubTokenMinter` at all. Measured directly: the container built from the plan's literal compose block exited immediately with

```
RuntimeError: create_app refuses to start with StubTokenMinter against a
production-shaped configuration (customer_jwks_uri and customer_token_issuer
are both set)...
```

**Fix:** `services/api/settings.py::Settings.from_env()` now reads both with `os.environ.get(...) or None`, collapsing "absent" and `""` to `None`. Proven with two new tests in `tests/test_server_assembly.py` (`test_settings_from_env_treats_missing_jwks_and_issuer_as_no_auth`, `test_settings_from_env_treats_empty_string_jwks_and_issuer_as_no_auth`) and by running the container: with the fix, the same empty-string environment starts cleanly and serves `tools/list`.

**2. Even fixed, a genuinely auth-less stack can never complete a tool call.** This is a second, previously undocumented gap, found only by driving a real `tools/call` against the running container. `create_app()`'s production path always wires `services/api/server.py::token_customer_resolver`, which unconditionally calls `fastmcp.server.dependencies.get_access_token()`. That function returns `None` on every request when no auth provider is configured at all (there is no validated `AuthenticatedUser` for it to read off `request.scope["user"]`, confirmed by reading `fastmcp/server/dependencies.py::get_access_token` directly). So `auth=None` lets the process start and answer `tools/list` (no customer needed), but every one of the five tools calls `resolver()` and gets:

```json
{"result":{"content":[{"text":"Error calling tool 'accounts.list': request carries no validated access token","type":"text"}],"isError":true, ...}}
```

There is no environment-variable-driven way around this: `create_app(resolver=...)`'s test seam is a keyword-only Python parameter, not reachable from `uvicorn services.api.main:app`.

**Fix (compose-only, no further application code changed): a disposable local identity provider inside `stub/backend.py`.** `RSAKeyPair.generate()` (already vendored in `fastmcp.server.auth.providers.jwt`, used here only as a convenient RSA-keypair-plus-JWT-minting helper) backs two new routes, clearly separated in the file from the domain-data routes and documented as a different concern (handoff §7.1: the customer-facing OAuth axis, not the backend-facing Vault axis this stub otherwise stands in for):

- `GET /.well-known/jwks.json` -- serves the public key as a JWKS.
- `GET /mint-token?sub=cust_7f3a` -- mints an `RS256` JWT against the same keypair, reading `POSTERN_TOKEN_ISSUER`/`POSTERN_AUDIENCE` from its own environment so the token and the `api` service's `JWTVerifier` agree without hardcoding the same string in two files.

`docker-compose.yml`'s `api` service now points `POSTERN_JWKS_URI` at that JWKS endpoint and sets a real (if throwaway) `POSTERN_TOKEN_ISSUER`. That makes the configuration "production-shaped" by `_refuse_stub_minter_in_production`'s own definition, so `POSTERN_ALLOW_STUB_TOKEN_MINTER=1` is also set -- exactly the scenario that flag's own docstring names ("real customer auth already live, backend still a controlled sandbox"), acceptable only because the backend is `backend-stub`, the stack binds to localhost, and the JWKS keypair is regenerated fresh on every container start.

The genuinely-empty-string no-auth path is not dead code: it is still real (proven by the two settings tests above) and would still be useful for iterating on `tools/list`, the header/body middleware, or the body-size limit alone. It is simply not what `docker-compose.yml` uses by default, because doing so would make every real tool call fail by design, and this task's job is to prove one succeeds.

## Proof: a real masked `tools/call` through the running stack

`docker compose up --build -d`, then, with a token minted from the running `backend-stub`:

```
$ TOKEN=$(curl -sS "http://localhost:8081/mint-token?sub=cust_7f3a")
$ curl -sS http://localhost:8080/mcp \
    -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
    -H 'MCP-Protocol-Version: 2026-07-28' -H 'Mcp-Method: tools/call' -H 'Mcp-Name: accounts.list' \
    -H "Authorization: Bearer $TOKEN" \
    -d '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"accounts.list","arguments":{},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}'
```

```json
{"jsonrpc":"2.0","id":3,"result":{"content":[{"text":"[{\"ref\":\"acc_7f3a\",\"label\":\"Joint expenses\",\"iban\":\"ES•• •••• 1332\"},{\"ref\":\"acc_9b21\",\"label\":\"Savings\",\"iban\":\"ES•• •••• 1119\"}]","type":"text"}],"isError":false, ...}}
```

`stub/backend.py`'s `ACCOUNTS` fixture holds the raw `ES9121000418450200051332`; the response carries only `ES•• •••• 1332`. The raw value appears nowhere on the wire. `transactions.list` (whose fixture embeds a full PAN and IBAN in `description`, matching `tests/fixtures/backend_responses.py` exactly) and `cards.list` were also driven manually and came back masked (`"description":"Card •••• 4417 purchase, ref DE•• •••• 3000"`, `"pan":"•••• 4417"`) -- not required by this task's own checklist, but free additional evidence the same masking property holds outside `accounts.list`.

## Non-root and read-only root filesystem

Both confirmed by running the built image, not by reading the Dockerfile:

```
$ docker run --rm --platform linux/arm64 postern-api:dev id
uid=1000 gid=1000 groups=1000
```

```
$ docker run -d --read-only --platform linux/arm64 \
    -e POSTERN_BACKEND_BASE_URL=http://example.invalid \
    -e POSTERN_JWKS_URI="" -e POSTERN_TOKEN_ISSUER="" \
    -p 18080:8080 postern-api:dev
$ curl ... -> HTTP 200
```

No writable `/tmp` or other writable mount was needed: `PYTHONDONTWRITEBYTECODE=1` (set in the Dockerfile) stops the interpreter from attempting to write `.pyc` files under the read-only tree, and nothing else in the request path touches the filesystem.

## Image size: what dominates it

`postern-api:dev` and `postern-confirm:dev` are both **322MB** (`docker images`). `docker history --no-trunc` on the built image breaks that down:

| Layer | Size | What it is |
|---|---|---|
| `debian.sh --arch arm64 ... trixie` | 109MB | The `python:3.12-slim` base's own Debian root filesystem |
| `apt-get install ... dpkg-dev g++ gcc ... && ./configure && make && make install` | 44.6MB | `python:3.12-slim`'s own CPython-from-source build (build tools are purged after, this is what remains) |
| `apt-get install ca-certificates netbase tzdata` | 13.1MB | `python:3.12-slim`'s own TLS/timezone layer |
| `COPY --from=builder /app /app` | 86.8MB | This project's own contribution: the `.venv` (83MB) plus `services/`, `packages/`, `pyproject.toml`, `uv.lock` (under 500KB combined) |

So roughly half the image (166.7MB) is `python:3.12-slim` itself, unchanged by anything this task controls; the other half is this project's dependency tree. Inside the venv, the largest individual packages are `uvloop` (16MB), `cryptography` (14MB), `beartype` (5.5MB), `pygments` (5.1MB) and `pydantic_core` (4.3MB) -- all transitive dependencies of `fastmcp`/`uvicorn[standard]`, not something this task's dependency list added. `.dockerignore` was tightened during this task (see "Adversarial pass" below) to drop `CLAUDE.md`, `README.md`, `Makefile`, `Dockerfile`, `.importlinter` and `.python-version` from the image; that saves under 30KB, i.e. it is a hygiene fix, not a size fix -- the image's size is set by the base OS and the dependency graph, not by stray root files.

## Adversarial pass

**No secret, `.env`, `.venv` (host), `.git` or test material in the image.** Verified by listing the built image's filesystem directly, not by trusting `.dockerignore`:

```
$ docker run --rm --platform linux/arm64 postern-api:dev sh -c "ls -al /app"
.venv/  packages/  pyproject.toml  services/  uv.lock
```

`.venv` here is the container's own venv, built inside the image by `uv sync`, not a bind-mounted host directory (the `Dockerfile` has no bind mounts; only `docker-compose.yml`'s dev-only `backend-stub` service uses one, and it anonymous-volumes over `.venv` specifically to stop a host-built venv from leaking in). No `tests/`, `docs/`, `stub/`, `tools/`, `.claude/`, `.git`, `.env*`, or Python/mypy/ruff/import-linter cache directories are present -- `.dockerignore` excludes all of them from the build context, so `COPY . .` never sees them in the first place.

**`--frozen` does honour `uv.lock`, but not the way a first guess suggests.** Tested by editing `pyproject.toml` to add a dependency absent from `uv.lock` (`boltons>=25.0`, confirmed absent by grepping the lockfile first) and rebuilding with `--no-cache`: the build **succeeded**, and `boltons` was confirmed **not installed** in the resulting image (`ls .venv/.../site-packages | grep boltons` -> no match). `uv sync --frozen` does not compare `pyproject.toml` against `uv.lock` for consistency at all -- it simply refuses to *write* a new lock and installs exactly what the existing lockfile already resolves, silently ignoring any dependency the lockfile doesn't already know about. This still delivers the property that matters for a Docker build (the image's dependency set is always exactly what `uv.lock` says, never a resolution computed fresh at build time, so it cannot drift from what was committed and reviewed) -- but it means the Docker build itself will never catch a developer who bumped `pyproject.toml` and forgot to run `uv lock`. That check already exists as a separate, earlier gate: `make lock` runs `uv lock --check --offline`, which does fail on exactly this mismatch, and is one of the six gates `make ci` already runs before any commit. The (reverted) probe edit to `pyproject.toml` was never committed; `git status`/`git diff` were checked clean before and after.

**A missing required `POSTERN_*` variable fails fast, by name, before binding a port.** `POSTERN_BACKEND_BASE_URL` has no default: `Settings.from_env()` reads it via a bare `os.environ[...]`, so an incomplete environment fails at the `Settings.from_env()` call inside `create_app()`'s lazy `__getattr__`, which `uvicorn services.api.main:app` triggers at import time, before startup completes -- `KeyError: 'POSTERN_BACKEND_BASE_URL'`, not a first-request failure. `POSTERN_JWKS_URI`/`POSTERN_TOKEN_ISSUER` are the deliberate exception (see above): they are optional by design, and their absence is not an error, it is the no-auth path.

**Amendment, 2026-09-18: `_refuse_stub_minter_in_production` (referenced above at "Two things the plan's compose environment got wrong", including the quoted `RuntimeError`) no longer exists.** `d203606` ("refactor(api): delete the stub-minter startup guard and its flag") deleted it along with `Settings.allow_stub_token_minter` (env `POSTERN_ALLOW_STUB_TOKEN_MINTER`). The guard read a settings shape (`customer_jwks_uri` and `customer_token_issuer` both set), never which minter `create_app` actually built, so once `StubTokenMinter` stopped being constructed there it refused exactly the deployments running the genuine `ReadTokenMinter` (`services/api/main.py:21-30`). The `POSTERN_ALLOW_STUB_TOKEN_MINTER: "1"` line this record describes above in the compose `api` service is also gone: `d203606` removed it from `docker-compose.yml`, and the file at HEAD (checked directly) sets no `POSTERN_ALLOW_STUB_TOKEN_MINTER` anywhere. Nothing checks production shape at startup now -- no replacement control exists.

**Further amendment, 2026-09-18: the compose stack now warns at startup, in both services.** `postern_core.auth.keys.warn_ephemeral_signing_key` emits a `RuntimeWarning` whenever a composition root builds an in-process signing key, called from `services/api/main.py::_read_key_source` and `services/confirm/minter.py::_write_key_source` on the line after `GeneratedKeySource(...)` returns. `docker-compose.yml` sets neither `POSTERN_READ_KEY_PEM_PATH` on `api` (its `environment` block is six variables, none of them a PEM path) nor `POSTERN_WRITE_KEY_PEM_PATH` on `confirm` (which sets no environment at all, and whose comment already says the omission is deliberate), so both containers take the generated branch and both warn. The message names the consequence measured in `docs/verification/2026-09-18-multi-replica-jwks.md`: the key dies with the process, differs per replica, and the `kid` (`read-1` / `write-1`) stays fixed because it comes from a settings default, so a token minted by one replica fails against another's JWKS as `joserfc.errors.BadSignatureError('bad_signature: ')` rather than as an `InvalidKeyIdError` naming a key mismatch. It goes to stderr through `warnings.showwarning`, which is where `docker compose logs` reads a container's output from; no container was run in the session that added it, so the rendered log line is **inferred, not measured**.

**What this does and does not restore.** It WARNS and never refuses, which is the difference that matters to this record: the failure documented above under "Two things the plan's compose environment got wrong" was a container exiting immediately on a `RuntimeError`, and nothing here can produce that -- `docker compose up` starts exactly as before, just louder. It is unconditional, so no environment variable turns it off and there is no override flag; that is deliberate, since an override flag is what `POSTERN_ALLOW_STUB_TOKEN_MINTER` was. It covers ephemeral signing keys ONLY. It restores no check on which minter `create_app` built and none on deployment shape, so the thing `_refuse_stub_minter_in_production` nominally did is still done by nothing, and the amendment above stays accurate on that point. Proof: `tests/test_ephemeral_key_warning.py`, 8 tests.

**Third amendment, 2026-09-18: a startup control that can stop a container now exists, and this compose stack is the shape the old one broke on.** `postern_core.auth.minter_probe.refuse_unverifiable_minter`, called from `services/api/main.py::create_app`, mints one token and raises `RuntimeError` if it does not verify against the key set the same process publishes -- so unlike the ephemeral-key warning, this one can produce exactly the failure this record documents above under "Two things the plan's compose environment got wrong": a container exiting immediately. It does not produce it here. The `api` service's `environment` block sets six variables and none of them selects a minter, so that container builds the same `ReadTokenMinter` over the same `GeneratedKeySource` as every other caller of `create_app`, and the probe verifies its token. The two variables the deleted guard refused on, `POSTERN_JWKS_URI` and `POSTERN_TOKEN_ISSUER`, are both still set in that block and are now read by nothing in this path: `tests/test_startup_minter_probe.py::test_the_genuine_minter_starts_under_either_settings_shape[production_shaped]` pins that shape in process. No container was started in the session that added this, so the compose behaviour is **inferred from that test and the environment block, not measured**. There is no flag to set: `POSTERN_ALLOW_STUB_TOKEN_MINTER` has no successor, and the compose file needs no new line.

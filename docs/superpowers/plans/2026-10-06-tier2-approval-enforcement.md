# Tier-2 Approval Enforcement Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `services/confirm` enforce a challenge row's tier at approval, as the accepted spec `docs/superpowers/specs/2026-10-06-tier2-approval-enforcement-design.md` and decision record `dev-docs/decisions/0023-tier-2-proof-in-the-app-assertion.md` describe: a row below its operation's declared tier is refused (`tier_mismatch`), tier 0 is refused (`tier_unsupported`), tier 1 is unchanged, and tier 2 needs four claims in the verified banking-app assertion (`idv`, `challenge_id`, `jti`, `auth_time`), with the `jti` stored as `verification_result` and recorded in the audit row. Producer rollout gate 1 is then met; gates 2 and 3 are untouched.

**Architecture:** One new setting, `POSTERN_CONFIRM_IDV_VALUE` (`ConfirmSettings.idv_value`), validated in `__post_init__` and in `from_env`, warned about at startup when unset. One new module, `services/confirm/tier_proof.py`, holding a pure `check_tier` (no I/O, no clock, no logging) that returns a `TierVerdict`, and `tier_refusal`, which builds the 403 and logs one WARNING naming the failed claim. `_approve` in `services/confirm/callback.py` calls it between the device-signature check and the claiming `UPDATE`, inside the same session, and passes the stored `verification_result` through. `ApprovalAudit` gains `note_assertion_jti`, which puts the `jti` into both audit rows' `arguments`. No migration, no schema change, no change to the write token.

**Tech Stack:** Python 3.12, Starlette, FastMCP 4.0.3 `JWTVerifier` and `RSAKeyPair.create_token(additional_claims=...)`, SQLAlchemy 2.0 async with asyncpg, `httpx2` ASGI and mock transports, testcontainers Postgres through `tests/conftest.py`.

---

## Before you start: rules that apply to every task

1. **Work in the worktree `/Users/stefano/Projects/postern/.claude/worktrees/tier2-enforcement`**, branch `worktree-tier2-enforcement`. One writer per worktree: no other session edits it while a task runs. Commit once per task with exactly the `git add` list given. **No push, no stash, no tag, and nothing that triggers GitHub Actions.**
2. **The sandbox refuses heredocs and compound commands.** Run one command per Bash call, exactly as written below. The single exception is the `make ci` line, which is given in the form `make ci > <log> 2>&1; echo EXIT=$?`; if the sandbox refuses it, run `make ci` alone and read its last line. Any helper script goes in the session scratchpad, `/private/tmp/claude-501/-Users-stefano-Projects-postern/dce26918-b575-4415-8de8-976663bf0f78/scratchpad`, never in the tree.
3. **A "replace" step is an exact-text substitution, and every quoted old text occurs exactly once in its file** (each was counted against b05d406). If an anchor does not occur exactly once, **stop and report the drift**: the tree has moved and the step must be re-derived, not guessed. This is how the previous plan went wrong (its errata list a missed hand-kept set entry, import blocks that no longer matched after a review fixup, and a test helper whose typing failed mypy).
4. **TDD in Tasks 2 to 4:** write the failing test, run it and see the stated failure, implement, run it and see it pass, run the mutation step, run the gates, run `make ci`, commit. Task 1 is a fixture change whose tests pass before and after; Task 5 is documentation.
5. **Mutation steps** apply one named edit to the code under test with the Edit tool, run the named test alone, require it to FAIL, then apply the reverse edit with the Edit tool. Never restore with `git checkout` or `git restore`: the file holds the task's uncommitted work.
6. **Format with `uv run ruff format packages services tests`**, scoped, and fix import order with `uv run ruff check --fix <the files you touched>`. Never run `make fmt` (unscoped; it rewrites the code fences in the markdown documents, this plan included).
7. **`make citations` scans this plan and every doc you edit.** Every NEW symbol is named here in plain backticks and never in the anchored forms (a path followed by two colons and a name, or a backticked `.py` path followed by an apostrophe-s and a backticked name), and no bare `<file>.py:<line>` appears, because the new plan file has no allowance in `tools/citations-baseline.json`. Do not regenerate that baseline (`make citations-baseline` is forbidden in this plan). `uv run pytest ...` command lines are exempt from the anchored rule.
8. **No em-dashes** in any prose, comment, docstring, log message or commit message you write.
9. **Commit messages** end with a blank line and then exactly `Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>`. The two `-m` form below produces that.
10. **Each task is followed by an independent review** (not written here). A review fixup that changes code a later task quotes as an anchor means the later anchor must be re-checked before use (rule 3).

## Facts this plan relies on, resolved against the code at b05d406

Every code block in this plan was applied to a copy of the tree at b05d406 and run there: `make lint fmt-check type imports citations` passed, the whole suite gave `4727 passed` in 338 s (4616 before, plus 28, 46 and 37 new tests), and each of the twelve mutations the spec lists failed at least one test.

- **(a) The spec's statement that `tests/test_payments_approval_path.py` "is the only test that fails under the new rule" is false.** It was measured for a rule that refused non-tier-1 rows; the `tier_mismatch` rule added after the review also refuses every `payments.create_payment` row stored at tier 1, and nine existing test files store exactly that as a generic write fixture. Measured with the rule applied to the unchanged suite: **57 failed** (`tests/test_payments_approval_path.py` plus 56 in `tests/test_approval_concurrency.py`, `tests/test_approval_integration.py`, `tests/test_callback.py`, `tests/test_confirm_body_limit.py`, `tests/test_device_signature.py`, `tests/test_pool_sizing.py`, `tests/test_write_audit.py`, `tests/test_write_audit_arguments_cap.py`, `tests/test_zt7_confirm_revocation.py`). Task 1 moves those fixtures to `standing_orders.cancel`, a tier-1 built-in with the same audience (`payments.svc`) and the same write scope, so the tests keep measuring what they measured. Two of the nine files (`tests/test_confirm_body_limit.py`, `tests/test_write_audit_arguments_cap.py`) import their seed helper from `tests/test_write_audit.py` and need no edit of their own. None of the nine asserts the `/payments` path or the executed message's tool name (checked by grep). After Task 1, with the rule applied, all 228 tests of those files plus `tests/test_audit_reserve.py` pass.
- **(b) Insertion point.** In `services/confirm/callback.py`, `_approve` runs revocation (line 444), signature presence (457), `get_challenge` (465), ownership (495), signature verify (533 to 537), claiming `UPDATE` (550 to 562), commit (576). Line 538 is blank and 539 opens the claim comment, as the spec says; the worktree is 46cb87d plus documentation only. `verified_claims` is imported at line 134, `request` and `audit` are in scope, `time` is already imported, and `request.app.state.settings` is the `ConfirmSettings` the app was built with (also in `tests/test_callback.py`'s mock state, which sets `ConfirmSettings.for_testing()`).
- **(c) Tier 0 is reachable as `tier_unsupported` only for an operation confirm does not declare.** Spec section 5 applies `tier_mismatch` first, and every declared tier is 1 or 2, so a tier-0 row of a declared operation is a mismatch. The tier-0 HTTP test therefore uses an undeclared tool name, `test.unregistered_write`.
- **(d) `math.isfinite` raises `OverflowError` on an `int` too large for a float** (`math.isfinite(10**400)`, measured), and `10**400` is a valid JSON number. The `auth_time` check tests finiteness on a `float` only; every `int` is finite and compares exactly. `services/confirm/auth.py` has the same pattern in `_is_time` for `exp`, `iat` and `nbf`; that is pre-existing, out of scope, and not changed here.
- **(e) Claims travel through the real verifier as sent.** Measured with `RSAKeyPair.create_token(additional_claims=...)` and `JWTVerifier.verify_token`: `nan`, `inf`, `-inf`, `True`, `None`, a NUL inside a string and a float all arrive in `claims` unchanged, so the HTTP tests can send each.
- **(f) A uuid4 hex challenge id can be partly masked by the audit scrub** (a twelve-digit run, an eight-digit DNI shape, or a letter-letter-digit-digit opener). Measured: with hex ids, three of 37 HTTP tests failed to find their audit rows by `arguments["challenge_id"]` in one run. The HTTP tests map the hex digits to letters.
- **(g) `ApprovalAudit` builds `arguments` in its constructor**, before the tier is known, and `_arguments` keeps its signature because `tests/test_write_audit_arguments_cap.py` imports it. `note_assertion_jti` therefore re-derives `arguments` from what was built, putting `assertion_jti` right after the three server-chosen keys (`route`, `challenge_id`, `signature_present`) for the first-fit reason `_arguments` documents, and re-bounds with `bound_arguments` unless the tree already carries the truncation marker.
- **(h) Counts in `tests/test_settings_bounds.py`.** A new confirm-only string moves `KNOWN_ENV` 84 to 85 (asserted twice), `READ_AS_STRING` 32 to 33, `names_read_by("confirm")` 63 to 64, the reader union stays 52, and the prose at lines 28 to 29, 2119 to 2121 and 2209. The name also joins the hand-kept `not_numeric` set in `test_every_variable_from_env_reads_is_covered_or_deliberately_not` (the previous plan missed this step for its flag). The prose at line 2140 ("The 18 strings") is older than this change and stays as it is.
- **(i) The spec has two leftovers from before the claim was renamed to `idv`:** section 9 says the assertion "must carry `acr`", and section 7 lists the claims a log line may name as `acr`, `challenge_id` or `jti`. This plan uses `idv` throughout and logs whichever of the four claims failed.
- **(j) Rate limits do not interfere.** Each HTTP test builds its own confirm app, whose in-memory per-customer limit is 10 approvals a minute; no test sends more than two.

## File structure

Created:

| File | Responsibility |
|---|---|
| `services/confirm/tier_proof.py` | `check_tier` (pure), `TierVerdict`, `TierRefusal`, `tier_refusal`, the error codes and fixed descriptions. |
| `tests/test_tier2_settings.py` | The setting: construction, environment, startup warning. |
| `tests/test_tier_proof.py` | The rule as a pure function, bounds exact. |
| `tests/test_tier2_approval.py` | Every row of spec section 11 through the real confirm app and Postgres. |

The spec names one new test file; this plan splits it in three so that no task appends to a file an earlier task's review may have rewritten (the cause of the previous plan's import-block errata). Every section 11 row is still covered; the self-review maps each one.

Modified: `services/confirm/settings.py`, `services/confirm/main.py`, `services/confirm/audit.py`, `services/confirm/callback.py`, `services/confirm/auth.py`, `services/confirm/execute.py`, `packages/postern-core/src/postern_core/env_inventory.py`, `packages/postern-core/src/postern_core/store/challenges.py`, `packages/postern-core/src/postern_core/store/models.py`, `packages/postern-core/src/postern_core/domain/verification.py`, `docker-compose.yml`, seven existing test files in Task 1, `tests/test_settings_bounds.py`, `tests/test_payments_approval_path.py`, `CLAUDE.md`, `docs/user-guide/getting-started.md`, `docs/user-guide/components/confirm-service.md`, `docs/integration/mobile-app-pairing-contract.md`, `docs/superpowers/specs/2026-10-04-payments-producer-core-design.md`.

Not modified, on purpose: `dev-docs/decisions/0023-tier-2-proof-in-the-app-assertion.md` (already Accepted and aligned with the spec), the producer plan `docs/superpowers/plans/2026-10-04-payments-producer-core.md` (a dated record), `postern_core.domain.verification.Challenge.approve` (spec section 3), `tool-surface.json` (no write operation changes).

---

### Task 1: Move the tier-1 approval fixtures off `payments.create_payment`

Fact (a). Without this, Task 4's `tier_mismatch` rule turns 56 existing tests red. This task changes test fixtures only and passes on the tree as it is.

**Files:**
- Modify: `tests/test_callback.py`, `tests/test_approval_integration.py`, `tests/test_approval_concurrency.py`, `tests/test_pool_sizing.py`, `tests/test_device_signature.py`, `tests/test_write_audit.py`, `tests/test_zt7_confirm_revocation.py`

- [ ] **Step 1: `tests/test_callback.py`**

Replace

```python
    tool_name: str = "payments.create_payment",
    payload: dict[str, Any] | None = None,
```

with

```python
    tool_name: str = "standing_orders.cancel",
    payload: dict[str, Any] | None = None,
```

and replace

```python
        payload=payload or {},
```

with

```python
        payload=payload or {"order_id": "so_1"},
```

- [ ] **Step 2: `tests/test_approval_integration.py`**

Replace

```python
    tool_name: str = "payments.create_payment",
```

with

```python
    tool_name: str = "standing_orders.cancel",
```

Replace

```python
        payload=payload or {"amount": "EUR 340.00"},
```

with

```python
        payload=payload or {"order_id": "so_340"},
```

Replace

```python
        challenge_id="chal_int_expired",
        customer_ref="cust_7f3a",
        tool_name="payments.create_payment",
        payload={"amount": "EUR 10.00"},
```

with

```python
        challenge_id="chal_int_expired",
        customer_ref="cust_7f3a",
        tool_name="standing_orders.cancel",
        payload={"order_id": "so_10"},
```

The cross-customer expired fixture (`chal_int_xcust_expired`) keeps `payments.create_payment`: it is refused by the ownership check, which runs before the tier check.

- [ ] **Step 3: `tests/test_approval_concurrency.py`**

Replace

```python
            tool_name="payments.create_payment",
            payload={"amount": "EUR 340.00", "payee_ref": "payee_7"},
```

with

```python
            tool_name="standing_orders.cancel",
            payload={"order_id": "so_7", "reason": "no longer needed"},
```

- [ ] **Step 4: `tests/test_pool_sizing.py`**

Replace

```python
            tool_name="payments.create_payment",
            payload={"amount": "EUR 340.00"},
```

with

```python
            tool_name="standing_orders.cancel",
            payload={"order_id": "so_340"},
```

- [ ] **Step 5: `tests/test_device_signature.py`**

Replace

```python
TOOL = "payments.create_payment"
PAYLOAD: dict[str, Any] = {"amount": "EUR 340.00", "payee": "Acme Ltd"}
```

with

```python
TOOL = "standing_orders.cancel"
PAYLOAD: dict[str, Any] = {"order_id": "so_340", "amount": "EUR 340.00", "payee": "Acme Ltd"}
```

The body field `"tool_name": "payments.create_payment"` further down stays: it is an attacker's attempt to tell the server what to verify, and the test asserts it is ignored.

- [ ] **Step 6: `tests/test_write_audit.py`**

Replace

```python
TOOL = "payments.create_payment"
```

with

```python
TOOL = "standing_orders.cancel"
```

and replace

```python
                payload={"amount": "EUR 340.00", "payee": "Acme Ltd"},
```

with

```python
                payload={"order_id": "so_340", "amount": "EUR 340.00", "payee": "Acme Ltd"},
```

- [ ] **Step 7: `tests/test_zt7_confirm_revocation.py`**

Replace

```python
TOOL = "payments.create_payment"
```

with

```python
TOOL = "standing_orders.cancel"
```

and replace

```python
                payload={"amount": "EUR 340.00", "payee": "Acme Ltd"},
```

with

```python
                payload={"order_id": "so_340", "amount": "EUR 340.00", "payee": "Acme Ltd"},
```

- [ ] **Step 8: Run the affected files**

Run: `uv run pytest -q -rs tests/test_approval_concurrency.py tests/test_approval_integration.py tests/test_callback.py tests/test_confirm_body_limit.py tests/test_device_signature.py tests/test_pool_sizing.py tests/test_write_audit.py tests/test_write_audit_arguments_cap.py tests/test_zt7_confirm_revocation.py tests/test_audit_reserve.py`
Expected: `228 passed`.

- [ ] **Step 9: Gates**

Run: `uv run ruff format packages services tests`
Run: `make lint fmt-check type imports citations`
Expected: every gate passes.

- [ ] **Step 10: Full suite**

Run: `make ci > /private/tmp/claude-501/-Users-stefano-Projects-postern/dce26918-b575-4415-8de8-976663bf0f78/scratchpad/ci-task1.log 2>&1; echo EXIT=$?`
Expected: `EXIT=0`, and the log's test line reads `4616 passed`.

- [ ] **Step 11: Commit**

```bash
git add tests/test_callback.py tests/test_approval_integration.py tests/test_approval_concurrency.py tests/test_pool_sizing.py tests/test_device_signature.py tests/test_write_audit.py tests/test_zt7_confirm_revocation.py
git commit -m "test(confirm): approve tier-1 fixtures as standing_orders.cancel, not as a tier-1 payment" -m "Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>"
```

---

### Task 2: The setting `POSTERN_CONFIRM_IDV_VALUE`

Spec section 10.

**Files:**
- Create: `tests/test_tier2_settings.py`
- Modify: `services/confirm/settings.py`, `services/confirm/main.py`, `packages/postern-core/src/postern_core/env_inventory.py`, `tests/test_settings_bounds.py`, `docker-compose.yml`, `docs/user-guide/getting-started.md`, `docs/user-guide/components/confirm-service.md`

- [ ] **Step 1: Write the failing tests**

Create `tests/test_tier2_settings.py`:

```python
"""``POSTERN_CONFIRM_IDV_VALUE``: the value a tier-2 approval's ``idv`` claim must equal.

Spec docs/superpowers/specs/2026-10-06-tier2-approval-enforcement-design.md,
section 10, and decision record 0023. Unset is a legitimate state that refuses
every tier-2 approval and warns once at startup; a set value is 1 to 128
characters of printable ASCII, refused otherwise both from the environment and
when built in code.
"""

import dataclasses
import logging

import pytest
from fastmcp.server.auth.providers.jwt import JWTVerifier, RSAKeyPair
from postern_core.auth.device_keys import no_enrolled_devices

from services.confirm.main import create_confirm_app
from services.confirm.settings import (
    MAX_VISIBLE_ASCII_LENGTH,
    ConfirmSettings,
    is_visible_ascii,
    warn_if_idv_value_unset,
)

VARIABLE = "POSTERN_CONFIRM_IDV_VALUE"

#: Each is refused at construction. The last one carries a space, so it is
#: also the value the "never echoed" test looks for in the message.
REFUSED = [
    pytest.param("", id="empty"),
    pytest.param(" ", id="a-space"),
    pytest.param("idv value", id="an-inner-space"),
    pytest.param("idv\tvalue", id="a-tab"),
    pytest.param("idv\x00value", id="a-nul"),
    pytest.param("idv\x7fvalue", id="del"),
    pytest.param("idv\x1bvalue", id="a-control-character"),
    pytest.param("idv-é", id="non-ascii"),
    pytest.param("x" * (MAX_VISIBLE_ASCII_LENGTH + 1), id="129-characters"),
    pytest.param("SENTINEL VALUE", id="sentinel"),
]


def test_the_field_defaults_to_unset() -> None:
    assert ConfirmSettings().idv_value is None
    assert ConfirmSettings.for_testing().idv_value is None


@pytest.mark.parametrize("value", REFUSED)
def test_a_value_built_in_code_is_refused_naming_the_variable(value: str) -> None:
    with pytest.raises(ValueError) as raised:
        ConfirmSettings(idv_value=value)
    message = str(raised.value)
    assert VARIABLE in message
    assert "SENTINEL" not in message


@pytest.mark.parametrize(
    "value",
    [
        pytest.param("!", id="one-character"),
        pytest.param("~", id="the-top-of-the-range"),
        pytest.param("postern-dev-idv", id="ordinary"),
        pytest.param("x" * MAX_VISIBLE_ASCII_LENGTH, id="128-characters"),
    ],
)
def test_a_usable_value_is_stored_exactly_as_given(value: str) -> None:
    assert ConfirmSettings(idv_value=value).idv_value == value


def test_the_class_is_1_to_128_characters_from_0x21_to_0x7e() -> None:
    assert MAX_VISIBLE_ASCII_LENGTH == 128
    assert is_visible_ascii("".join(chr(code) for code in range(0x21, 0x7F)))
    assert not is_visible_ascii("")
    assert not is_visible_ascii("\x20")
    assert not is_visible_ascii("\x7f")
    assert is_visible_ascii("j" * 128)
    assert not is_visible_ascii("j" * 129)


def test_unset_in_the_environment_is_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(VARIABLE, raising=False)
    assert ConfirmSettings.from_env().idv_value is None


def test_empty_in_the_environment_is_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(VARIABLE, "")
    assert ConfirmSettings.from_env().idv_value is None


def test_a_value_in_the_environment_is_read_exactly(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(VARIABLE, "Postern-Dev-IDV")
    assert ConfirmSettings.from_env().idv_value == "Postern-Dev-IDV"


@pytest.mark.parametrize("value", [" ", "idv value", " idv", "idv\tvalue", "idv\x1bvalue"])
def test_a_value_in_the_environment_is_refused_naming_the_variable(
    value: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(VARIABLE, value)
    with pytest.raises(ValueError, match=VARIABLE):
        ConfirmSettings.from_env()


def test_unset_warns_once(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.WARNING, logger="services.confirm.settings"):
        warn_if_idv_value_unset(ConfirmSettings())
    (record,) = caplog.records
    assert record.levelno == logging.WARNING
    assert VARIABLE in record.getMessage()
    assert "tier-2" in record.getMessage()


def test_set_does_not_warn(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.WARNING, logger="services.confirm.settings"):
        warn_if_idv_value_unset(ConfirmSettings(idv_value="postern-dev-idv"))
    assert caplog.records == []


@pytest.mark.parametrize(("idv_value", "warnings"), [(None, 1), ("postern-dev-idv", 0)])
def test_the_composition_root_warns_exactly_when_unset(
    idv_value: str | None, warnings: int, caplog: pytest.LogCaptureFixture
) -> None:
    key_pair = RSAKeyPair.generate()
    settings = dataclasses.replace(ConfirmSettings.for_testing(), idv_value=idv_value)
    with caplog.at_level(logging.WARNING, logger="services.confirm.settings"):
        create_confirm_app(
            settings,
            assertion_verifier=JWTVerifier(
                public_key=key_pair.public_key,
                issuer="https://app.test.invalid",
                audience="postern-confirm",
            ),
            device_key_store=no_enrolled_devices(),
        )
    found = [r for r in caplog.records if VARIABLE in r.getMessage()]
    assert len(found) == warnings
```

In `tests/test_settings_bounds.py`, make these seven replacements.

Replace

```
shares, the variable's NAME at the read site. The swept tree names 84
``POSTERN_*`` variables in two disjoint populations: 32 read directly, all of
```

with

```
shares, the variable's NAME at the read site. The swept tree names 85
``POSTERN_*`` variables in two disjoint populations: 33 read directly, all of
```

Replace

```python
            "POSTERN_DEVICE_KEYS_PATH",
```

with

```python
            "POSTERN_DEVICE_KEYS_PATH",
            # The tier-2 approval value: a string compared exactly with an
            # assertion claim, with no range to leave.
            "POSTERN_CONFIRM_IDV_VALUE",
```

Replace

```
    WHAT THE TREE ACTUALLY HOLDS, counted rather than assumed: 84 distinct
    ``POSTERN_*`` variables across the swept roots, in two disjoint
    populations. 32 are read directly, and all 32 are strings -- a URL, a
```

with

```
    WHAT THE TREE ACTUALLY HOLDS, counted rather than assumed: 85 distinct
    ``POSTERN_*`` variables across the swept roots, in two disjoint
    populations. 33 are read directly, and all 33 are strings -- a URL, a
```

Replace

```python
        """84 variables, 32 read directly and 52 through a reader, disjoint."""
```

with

```python
        """85 variables, 33 read directly and 52 through a reader, disjoint."""
```

Replace

```python
        assert direct | through == set(KNOWN_ENV)
        assert len(KNOWN_ENV) == 84
```

with

```python
        assert direct | through == set(KNOWN_ENV)
        assert len(KNOWN_ENV) == 85
```

Replace

```python
        assert len(KNOWN_ENV) == 84
        assert len(READ_AS_STRING) == 32
```

with

```python
        assert len(KNOWN_ENV) == 85
        assert len(READ_AS_STRING) == 33
```

Replace

```python
        assert len(names_read_by("confirm")) == 63
```

with

```python
        assert len(names_read_by("confirm")) == 64
```

- [ ] **Step 2: Run them and see them fail**

Run: `uv run pytest -q -rs tests/test_tier2_settings.py`
Expected: a collection error, `ImportError: cannot import name 'MAX_VISIBLE_ASCII_LENGTH' from 'services.confirm.settings'`.

Run: `uv run pytest -q -rs tests/test_settings_bounds.py -k "whole_tree or docstrings_quote"`
Expected: 2 failed, each `assert 84 == 85`.

- [ ] **Step 3: The character class and the check**

In `services/confirm/settings.py`, replace

```python
#: The path the pairing page is served on, in ``services/confirm/verify_page.py``.
```

with

```python
#: The longest ``POSTERN_CONFIRM_IDV_VALUE`` this service accepts, and the
#: longest assertion ``jti`` a tier-2 approval accepts (decision record 0023).
#: Both are compared or stored exactly as given, so both are held to one
#: character class, `is_visible_ascii`.
MAX_VISIBLE_ASCII_LENGTH = 128


def is_visible_ascii(value: str, *, max_length: int = MAX_VISIBLE_ASCII_LENGTH) -> bool:
    """True when ``value`` is 1 to ``max_length`` characters, each 0x21 to 0x7E.

    That excludes every whitespace character, every control character, NUL
    included, DEL, and everything outside ASCII. NUL is the one with a
    measured consequence: PostgreSQL refuses it in a ``text`` value, so a NUL
    in a tier-2 ``jti`` would make the claiming ``UPDATE`` raise, and the 500
    that follows carries the statement and its bound parameters in its
    description (spec docs/superpowers/specs/2026-10-06-tier2-approval-enforcement-design.md,
    section 4).
    """
    return 1 <= len(value) <= max_length and all("!" <= char <= "~" for char in value)


def _check_idv_value(value: str | None) -> str | None:
    """Return ``value`` if it is unset or a usable ``POSTERN_CONFIRM_IDV_VALUE``, else raise.

    Called by ``ConfirmSettings.__post_init__`` and by ``from_env``, as
    `_check_app_link_uri` is, so a value built in code is held to the same
    rule as one read from the environment. From the environment an empty
    string is unset (``or None``); built in code, ``""`` is refused here.

    The value is never echoed. It is not a credential, but it is the one
    string a tier-2 approval must carry, and nothing about it needs to be in a
    log line to fix a refused setting: the rule below is the whole answer.
    """
    if value is None or is_visible_ascii(value):
        return value
    raise ValueError(
        "POSTERN_CONFIRM_IDV_VALUE must be 1 to 128 printable ASCII characters "
        "(0x21 to 0x7E): no whitespace, no control character, nothing outside ASCII. "
        "It is compared, exactly, with the idv claim of the banking-app assertion that "
        "approves a tier-2 challenge. Leave it unset to refuse every tier-2 approval."
    )


#: The path the pairing page is served on, in ``services/confirm/verify_page.py``.
```

- [ ] **Step 4: The field, its two checks and the warning**

In `services/confirm/settings.py`, replace

```python
    device_keys_path: str | None = None
```

with

```python
    device_keys_path: str | None = None
    # TIER-2 APPROVAL (decision record 0023). The value the banking-app
    # assertion's ``idv`` claim must equal, exactly, for a tier-2 challenge to
    # be approved. It is agreed with the operator's app backend and is not a
    # standard value; that backend must emit it in no other claim.
    #
    # NO DEFAULT, on purpose. Unset, every tier-2 approval is refused with
    # ``verification_required`` and the service still starts, with one
    # warning (`warn_if_idv_value_unset`): tier-1 approvals do not need it,
    # and this process cannot know whether the api runs with
    # POSTERN_PAYMENTS_ENABLED. `_check_idv_value` holds what a set value must be.
    idv_value: str | None = None
```

Replace

```python
        _check_app_link_uri(self.device_app_link_uri, self.device_verification_uri)
```

with

```python
        _check_app_link_uri(self.device_app_link_uri, self.device_verification_uri)
        _check_idv_value(self.idv_value)
```

Replace

```python
            device_keys_path=os.environ.get("POSTERN_DEVICE_KEYS_PATH") or None,
```

with

```python
            device_keys_path=os.environ.get("POSTERN_DEVICE_KEYS_PATH") or None,
            idv_value=_check_idv_value(os.environ.get("POSTERN_CONFIRM_IDV_VALUE") or None),
```

Replace (the end of `check_session_token_settings`, the last lines of the file)

```python
            "POSTERN_APP_ASSERTION_AUDIENCE: a token good enough to reach the MCP server "
            "must not be good enough to approve a payment."
        )
```

with

```python
            "POSTERN_APP_ASSERTION_AUDIENCE: a token good enough to reach the MCP server "
            "must not be good enough to approve a payment."
        )


def warn_if_idv_value_unset(settings: ConfirmSettings) -> None:
    """Log one WARNING when ``idv_value`` is unset, and nothing otherwise.

    CALLED BY ``create_confirm_app``, beside `check_session_token_settings`.
    A warning and not a refusal, for the reason the field's comment gives:
    tier-1 approvals work without it, and with it unset every tier-2 approval
    is refused, which is the safe default (spec section 14).
    """
    if settings.idv_value is None:
        logger.warning(
            "POSTERN_CONFIRM_IDV_VALUE is not set: every tier-2 challenge approval will be "
            "refused with verification_required. Tier-1 approvals are unaffected."
        )
```

- [ ] **Step 5: Warn at startup**

In `services/confirm/main.py`, replace

```python
from services.confirm.settings import ConfirmSettings, check_session_token_settings
```

with

```python
from services.confirm.settings import (
    ConfirmSettings,
    check_session_token_settings,
    warn_if_idv_value_unset,
)
```

and replace

```python
    check_session_token_settings(settings)
```

with

```python
    check_session_token_settings(settings)
    # A warning, not a refusal: without POSTERN_CONFIRM_IDV_VALUE every tier-2
    # approval is refused and every tier-1 approval still works (decision
    # record 0023).
    warn_if_idv_value_unset(settings)
```

- [ ] **Step 6: Inventory it**

In `packages/postern-core/src/postern_core/env_inventory.py`, replace

```python
    EnvVar("POSTERN_CONFIRM_DATABASE_POOL_SIZE", "number", ("confirm",)),
```

with

```python
    EnvVar("POSTERN_CONFIRM_DATABASE_POOL_SIZE", "number", ("confirm",)),
    EnvVar("POSTERN_CONFIRM_IDV_VALUE", "string", ("confirm",)),
```

and replace

```
#: against it by `tests/test_settings_bounds.py` on every run. 84 rows since
#: 2026-10-04: 32 strings (30 settings plus this guard's own two lists), 46
#: numbers, 6 flags, the sixth being ``POSTERN_PAYMENTS_ENABLED``, which
#: arrived with the payments producer. The eight ``POSTERN_VAULT_*`` rows below the device-code
```

with

```
#: against it by `tests/test_settings_bounds.py` on every run. 85 rows since
#: 2026-10-06: 33 strings (31 settings plus this guard's own two lists), 46
#: numbers, 6 flags. The sixth flag, ``POSTERN_PAYMENTS_ENABLED``, arrived with
#: the payments producer on 2026-10-04, and the thirty-first setting string,
#: ``POSTERN_CONFIRM_IDV_VALUE``, with tier-2 approval enforcement on
#: 2026-10-06. The eight ``POSTERN_VAULT_*`` rows below the device-code
```

- [ ] **Step 7: Say it in the compose stack**

In `docker-compose.yml`, replace

```yaml
      POSTERN_DEVICE_KEYS_PATH: /etc/postern/device-keys.json
```

with

```yaml
      POSTERN_DEVICE_KEYS_PATH: /etc/postern/device-keys.json
      # The value the banking-app assertion's `idv` claim must equal to approve
      # a tier-2 challenge (decision record 0023). A PLACEHOLDER agreed with
      # nobody: a deployment sets the value its own app backend emits, and it is
      # not a standard value. With nobody enrolled above, no approval reaches
      # this check in this stack anyway.
      POSTERN_CONFIRM_IDV_VALUE: "postern-local-dev-idv"
```

- [ ] **Step 8: The two user-guide rows**

In `docs/user-guide/getting-started.md`, replace

```
| `POSTERN_WRITE_KEY_PEM_PATH` | No | - | Path to the PEM file for signing internal write tokens |
```

with

```
| `POSTERN_CONFIRM_IDV_VALUE` | **Yes, before any tier-2 approval** | unset | The value the banking-app assertion's `idv` claim must equal, exactly, to approve a tier-2 challenge (decision record 0023). Agreed with your app backend; not a standard value. **1 to 128 printable ASCII characters** (0x21 to 0x7E), refused at startup otherwise. Unset, the service starts with one warning and refuses every tier-2 approval with `verification_required`; tier-1 approvals do not need it |
| `POSTERN_WRITE_KEY_PEM_PATH` | No | - | Path to the PEM file for signing internal write tokens |
```

In `docs/user-guide/components/confirm-service.md`, replace

```
(unless `POSTERN_ALLOW_NON_URI_AUDIENCE` is set) or that equals
`POSTERN_APP_ASSERTION_AUDIENCE`.
```

with

```
(unless `POSTERN_ALLOW_NON_URI_AUDIENCE` is set) or that equals
`POSTERN_APP_ASSERTION_AUDIENCE`.

It starts without `POSTERN_CONFIRM_IDV_VALUE` and logs one warning: every tier-2
challenge approval is then refused with `verification_required`, and tier-1
approvals are unaffected. A set value that is not 1 to 128 printable ASCII
characters is refused at startup.
```

- [ ] **Step 9: Run them and see them pass**

Run: `uv run pytest -q -rs tests/test_tier2_settings.py tests/test_settings_bounds.py tests/test_unknown_env_guard.py tests/test_confirm_service.py tests/test_settings_repr.py`
Expected: PASS; `tests/test_tier2_settings.py` contributes 28 tests.

- [ ] **Step 10: Mutations**

Mutation 1, "`< 128` for `<= 128`": in `services/confirm/settings.py` replace `1 <= len(value) <= max_length` with `1 <= len(value) < max_length`.
Run: `uv run pytest -q -rs tests/test_tier2_settings.py`
Expected: FAIL (`test_a_usable_value_is_stored_exactly_as_given[128-characters]` and `test_the_class_is_1_to_128_characters_from_0x21_to_0x7e`). Restore the original text.

Mutation 2, "no check at construction": in `services/confirm/settings.py` delete the line `        _check_idv_value(self.idv_value)`.
Run: `uv run pytest -q -rs tests/test_tier2_settings.py -k built_in_code`
Expected: FAIL, `DID NOT RAISE`. Restore the line.

- [ ] **Step 11: Gates**

Run: `uv run ruff format packages services tests`
Run: `uv run ruff check --fix services/confirm/settings.py services/confirm/main.py tests/test_tier2_settings.py tests/test_settings_bounds.py`
Run: `make lint fmt-check type imports citations`
Expected: every gate passes.

- [ ] **Step 12: Full suite**

Run: `make ci > /private/tmp/claude-501/-Users-stefano-Projects-postern/dce26918-b575-4415-8de8-976663bf0f78/scratchpad/ci-task2.log 2>&1; echo EXIT=$?`
Expected: `EXIT=0`, `4644 passed`.

- [ ] **Step 13: Commit**

```bash
git add services/confirm/settings.py services/confirm/main.py packages/postern-core/src/postern_core/env_inventory.py tests/test_tier2_settings.py tests/test_settings_bounds.py docker-compose.yml docs/user-guide/getting-started.md docs/user-guide/components/confirm-service.md
git commit -m "feat(confirm): read POSTERN_CONFIRM_IDV_VALUE, warn when it is unset" -m "Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>"
```

---

### Task 3: The rule as a pure function, and its four audit details

Spec sections 5 and 7. The function exists and is tested here; Task 4 wires it.

**Files:**
- Create: `services/confirm/tier_proof.py`, `tests/test_tier_proof.py`
- Modify: `services/confirm/audit.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/test_tier_proof.py`:

```python
"""The tier rule of decision record 0023 as a pure function (spec section 5).

No database and no app: every row here is built in memory and every clock is
passed in, so the bounds are tested exactly. `tests/test_tier2_approval.py`
drives the same rule through the real callback.
"""

import json
import logging
import math
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from postern_core.domain.verification import VerificationTier
from postern_core.modules.write import WriteOperation
from postern_core.payments import CREATE_PAYMENT_TOOL
from postern_core.store.models import ChallengeRecord

from services.confirm.audit import (
    DETAIL_TIER_MISMATCH,
    DETAIL_TIER_UNSUPPORTED,
    DETAIL_VERIFICATION_NOT_CONFIGURED,
    DETAIL_VERIFICATION_REQUIRED,
)
from services.confirm.execute import WRITE_OPERATIONS
from services.confirm.tier_proof import (
    TIER_MISMATCH_DESCRIPTION,
    TIER_UNSUPPORTED_DESCRIPTION,
    VERIFICATION_REQUIRED_DESCRIPTION,
    TierRefusal,
    TierVerdict,
    check_tier,
    tier_refusal,
)

IDV = "postern-dev-idv"
CHALLENGE = "t2_unit_0001"
JTI = "jti-unit-0001"
CREATED = datetime(2026, 10, 6, 12, 0, 0, tzinfo=UTC)
NOW = CREATED.timestamp() + 60
TIER_1_TOOL = "standing_orders.cancel"


def record(
    *, tier: int = 2, tool_name: str = CREATE_PAYMENT_TOOL, created_at: datetime = CREATED
) -> ChallengeRecord:
    return ChallengeRecord(
        challenge_id=CHALLENGE,
        customer_ref="cust_unit1",
        tool_name=tool_name,
        payload={},
        tier=tier,
        status="pending",
        created_at=created_at,
        expires_at=created_at + timedelta(seconds=300),
    )


def claims(**overrides: Any) -> dict[str, Any]:
    """The four claims a tier-2 approval needs, valid unless overridden."""
    base: dict[str, Any] = {
        "idv": IDV,
        "challenge_id": CHALLENGE,
        "jti": JTI,
        "auth_time": CREATED.timestamp() + 5,
    }
    base.update(overrides)
    return base


def without(name: str) -> dict[str, Any]:
    remaining = claims()
    del remaining[name]
    return remaining


def check(
    row: ChallengeRecord,
    claim_set: Mapping[str, Any],
    *,
    expected: str | None = IDV,
    now: float = NOW,
    operations: Mapping[str, WriteOperation] = WRITE_OPERATIONS,
) -> TierVerdict:
    return check_tier(
        record=row,
        challenge_id=CHALLENGE,
        claims=claim_set,
        expected_idv=expected,
        now=now,
        operations=operations,
    )


def required(claim: str) -> TierRefusal:
    return TierRefusal(
        error="verification_required",
        detail=DETAIL_VERIFICATION_REQUIRED,
        description=VERIFICATION_REQUIRED_DESCRIPTION,
        failed_claim=claim,
    )


MISMATCH = TierRefusal(
    error="tier_mismatch",
    detail=DETAIL_TIER_MISMATCH,
    description=TIER_MISMATCH_DESCRIPTION,
    failed_claim=None,
)


# -- Tier 1 is unchanged -----------------------------------------------------------


def test_a_tier_1_row_needs_no_claims() -> None:
    assert check(record(tier=1, tool_name=TIER_1_TOOL), {}) == TierVerdict(None, None)


def test_a_tier_1_row_ignores_tier_2_claims() -> None:
    assert check(record(tier=1, tool_name=TIER_1_TOOL), claims()) == TierVerdict(None, None)


def test_an_unset_value_does_not_touch_a_tier_1_row() -> None:
    row = record(tier=1, tool_name=TIER_1_TOOL)
    assert check(row, {}, expected=None) == TierVerdict(None, None)


def test_a_tier_1_row_of_an_undeclared_operation_is_left_to_the_executor() -> None:
    """`resolve_endpoint` refuses an unknown tool after the claim, as before."""
    row = record(tier=1, tool_name="test.unregistered_write")
    assert check(row, {}) == TierVerdict(None, None)


# -- Tier 2 --------------------------------------------------------------------------


def test_a_tier_2_row_with_all_four_claims_passes_and_returns_the_jti() -> None:
    assert check(record(), claims()) == TierVerdict(refusal=None, assertion_jti=JTI)


def test_an_unset_value_refuses_every_tier_2_row() -> None:
    assert check(record(), claims(), expected=None) == TierVerdict(
        refusal=TierRefusal(
            error="verification_required",
            detail=DETAIL_VERIFICATION_NOT_CONFIGURED,
            description=VERIFICATION_REQUIRED_DESCRIPTION,
            failed_claim=None,
        ),
        assertion_jti=None,
    )


@pytest.mark.parametrize(
    ("claim_set", "failed", "jti_recorded"),
    [
        pytest.param(without("idv"), "idv", False, id="idv-missing"),
        pytest.param(claims(idv=1), "idv", False, id="idv-not-a-string"),
        pytest.param(claims(idv="another-value"), "idv", False, id="idv-wrong"),
        pytest.param(claims(idv=IDV.upper()), "idv", False, id="idv-other-case"),
        pytest.param(claims(idv=f" {IDV}"), "idv", False, id="idv-padded"),
        pytest.param(claims(idv=""), "idv", False, id="idv-empty"),
        pytest.param(claims(idv=None), "idv", False, id="idv-null"),
        pytest.param(without("challenge_id"), "challenge_id", False, id="challenge-id-missing"),
        pytest.param(claims(challenge_id=1), "challenge_id", False, id="challenge-id-number"),
        pytest.param(
            claims(challenge_id="t2_unit_0002"), "challenge_id", False, id="challenge-id-other"
        ),
        pytest.param(without("jti"), "jti", False, id="jti-missing"),
        pytest.param(claims(jti=7), "jti", False, id="jti-number"),
        pytest.param(claims(jti=""), "jti", False, id="jti-empty"),
        pytest.param(claims(jti="j" * 129), "jti", False, id="jti-129-characters"),
        pytest.param(claims(jti="jti\x00x"), "jti", False, id="jti-nul"),
        pytest.param(claims(jti="jti x"), "jti", False, id="jti-space"),
        pytest.param(claims(jti="jti\x7f"), "jti", False, id="jti-del"),
        pytest.param(claims(jti="jti-é"), "jti", False, id="jti-non-ascii"),
        pytest.param(without("auth_time"), "auth_time", True, id="auth-time-missing"),
        pytest.param(claims(auth_time=True), "auth_time", True, id="auth-time-bool"),
        pytest.param(claims(auth_time="1790000000"), "auth_time", True, id="auth-time-string"),
        pytest.param(claims(auth_time=math.nan), "auth_time", True, id="auth-time-nan"),
        pytest.param(claims(auth_time=math.inf), "auth_time", True, id="auth-time-inf"),
        pytest.param(claims(auth_time=-math.inf), "auth_time", True, id="auth-time-minus-inf"),
        pytest.param(claims(auth_time=10**400), "auth_time", True, id="auth-time-huge-int"),
        pytest.param(
            claims(auth_time=CREATED.timestamp() - 31),
            "auth_time",
            True,
            id="auth-time-31s-before-creation",
        ),
        pytest.param(claims(auth_time=NOW + 31), "auth_time", True, id="auth-time-31s-ahead"),
    ],
)
def test_each_failed_claim_refuses_with_one_description(
    claim_set: dict[str, Any], failed: str, jti_recorded: bool
) -> None:
    verdict = check(record(), claim_set)
    assert verdict.refusal == required(failed)
    assert verdict.assertion_jti == (JTI if jti_recorded else None)


@pytest.mark.parametrize(
    "auth_time",
    [
        pytest.param(CREATED.timestamp() - 30, id="lower-bound"),
        pytest.param(NOW + 30, id="upper-bound"),
        pytest.param(int(CREATED.timestamp()), id="an-integer"),
    ],
)
def test_the_auth_time_bounds_are_inclusive(auth_time: float) -> None:
    assert check(record(), claims(auth_time=auth_time)) == TierVerdict(None, JTI)


def test_a_jti_of_exactly_128_characters_passes() -> None:
    jti = "j" * 128
    assert check(record(), claims(jti=jti)) == TierVerdict(None, jti)


def test_a_bool_auth_time_is_refused_where_the_integer_1_would_pass() -> None:
    """A row created one second after the epoch puts ``1`` inside the bounds,
    so the refusal of ``True`` is the bool rule and not the bounds."""
    epoch = datetime(1970, 1, 1, 0, 0, 1, tzinfo=UTC)
    row = record(created_at=epoch)
    assert check(row, claims(auth_time=1), now=1.0).refusal is None
    assert check(row, claims(auth_time=True), now=1.0).refusal == required("auth_time")


# -- The declared tier -------------------------------------------------------------


@pytest.mark.parametrize("tier", [0, 1])
def test_a_payment_row_below_its_declared_tier_is_a_mismatch(tier: int) -> None:
    assert check(record(tier=tier), claims()) == TierVerdict(MISMATCH, None)


def test_the_mismatch_reads_the_declared_tier_from_the_operations_given() -> None:
    declared = WriteOperation(
        tool_name="test.write",
        audience="payments.svc",
        path_template="/test",
        method="POST",
        tier=VerificationTier.APP_IDENTITY_VERIFICATION,
    )
    row = record(tier=1, tool_name="test.write")
    assert check(row, {}, operations={"test.write": declared}).refusal == MISMATCH
    assert check(row, {}, operations={}).refusal is None


def test_a_tier_2_row_of_a_tier_1_operation_needs_the_proof() -> None:
    row = record(tier=2, tool_name=TIER_1_TOOL)
    assert check(row, {}).refusal == required("idv")
    assert check(row, claims()) == TierVerdict(None, JTI)


def test_a_tier_0_row_of_an_undeclared_operation_is_unsupported() -> None:
    row = record(tier=0, tool_name="test.unregistered_write")
    assert check(row, claims()) == TierVerdict(
        TierRefusal(
            error="tier_unsupported",
            detail=DETAIL_TIER_UNSUPPORTED,
            description=TIER_UNSUPPORTED_DESCRIPTION,
            failed_claim=None,
        ),
        None,
    )


# -- What a refusal says -----------------------------------------------------------


def test_no_description_names_a_claim_or_the_configured_value() -> None:
    for description in (
        VERIFICATION_REQUIRED_DESCRIPTION,
        TIER_MISMATCH_DESCRIPTION,
        TIER_UNSUPPORTED_DESCRIPTION,
    ):
        assert IDV not in description
        for claim in ("idv", "challenge_id", "jti", "auth_time"):
            assert claim not in description


def test_a_claim_refusal_is_a_fixed_403_and_logs_the_claim_name(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.WARNING, logger="services.confirm.tier_proof"):
        response, detail = tier_refusal(CHALLENGE, required("jti"))
    assert response.status_code == 403
    assert json.loads(bytes(response.body)) == {
        "error": "verification_required",
        "error_description": VERIFICATION_REQUIRED_DESCRIPTION,
    }
    assert detail == DETAIL_VERIFICATION_REQUIRED
    (logged,) = caplog.records
    assert logged.levelno == logging.WARNING
    assert CHALLENGE in logged.getMessage()
    assert "jti claim" in logged.getMessage()


def test_a_row_refusal_logs_its_detail(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.WARNING, logger="services.confirm.tier_proof"):
        response, detail = tier_refusal(CHALLENGE, MISMATCH)
    assert response.status_code == 403
    assert json.loads(bytes(response.body))["error"] == "tier_mismatch"
    assert detail == DETAIL_TIER_MISMATCH
    (logged,) = caplog.records
    assert "tier_mismatch" in logged.getMessage()
```

- [ ] **Step 2: Run it and see it fail**

Run: `uv run pytest -q -rs tests/test_tier_proof.py`
Expected: a collection error, `ImportError: cannot import name 'DETAIL_TIER_MISMATCH' from 'services.confirm.audit'`.

- [ ] **Step 3: The four audit details**

In `services/confirm/audit.py`, replace

```python
DETAIL_UPDATE_MATCHED_NO_ROW = "update_matched_no_row"
```

with

```python
DETAIL_UPDATE_MATCHED_NO_ROW = "update_matched_no_row"
#: THE FOUR THE TIER CHECK OWNS (decision record 0023), each decided after the
#: device signature verified and before the claim, so none of them moves the
#: challenge. The caller sees two codes for the first two and one each for the
#: others; the table tells all four apart.
#:
#: ``verification_required`` is a tier-2 row whose assertion did not carry the
#: four claims with acceptable values. Which claim failed is in the WARNING
#: log line, never here and never in the response.
DETAIL_VERIFICATION_REQUIRED = "verification_required"
#: ``verification_not_configured`` is a tier-2 row on a service with no
#: ``POSTERN_CONFIRM_IDV_VALUE``: an operator's setting, not a caller's
#: failure, which is why it is not the literal above.
DETAIL_VERIFICATION_NOT_CONFIGURED = "verification_not_configured"
#: ``tier_mismatch`` is a row stored below the tier its operation declares.
#: No path in this repository writes one; ``postern_app`` holds ``UPDATE`` on
#: ``challenges``, so a row like this is what a compromise of a process
#: holding that role leaves behind. Alert on it.
DETAIL_TIER_MISMATCH = "tier_mismatch"
#: ``tier_unsupported`` is a tier-0 row of an operation confirm does not
#: declare. Tier 0 is a read tier and nothing approves it.
DETAIL_TIER_UNSUPPORTED = "tier_unsupported"
```

Replace

```python
    "DETAIL_STORED_IDENTITY_MALFORMED",
    "DETAIL_UPDATE_MATCHED_NO_ROW",
```

with

```python
    "DETAIL_STORED_IDENTITY_MALFORMED",
    "DETAIL_TIER_MISMATCH",
    "DETAIL_TIER_UNSUPPORTED",
    "DETAIL_UPDATE_MATCHED_NO_ROW",
```

Replace

```python
    "DETAIL_USER_CODE_NOT_FOUND",
    "PairingAudit",
```

with

```python
    "DETAIL_USER_CODE_NOT_FOUND",
    "DETAIL_VERIFICATION_NOT_CONFIGURED",
    "DETAIL_VERIFICATION_REQUIRED",
    "PairingAudit",
```

- [ ] **Step 4: Run it and see the next failure**

Run: `uv run pytest -q -rs tests/test_tier_proof.py`
Expected: a collection error, `ModuleNotFoundError: No module named 'services.confirm.tier_proof'`.

- [ ] **Step 5: The module**

Create `services/confirm/tier_proof.py`:

```python
"""The tier a challenge row needs at approval, and whether the assertion proves it.

Spec docs/superpowers/specs/2026-10-06-tier2-approval-enforcement-design.md,
section 5, and decision record 0023. ``services/confirm/callback.py`` calls
`check_tier` between the device-signature check and the claiming ``UPDATE``,
so every refusal here leaves the row ``pending`` and the customer can retry
inside the tier's window.

THE RULE, in the order it is applied:

1. A row whose tier is below the tier its operation declares is refused,
   ``tier_mismatch``. The declared tier is static configuration in this
   process (`services.confirm.execute`'s ``WRITE_OPERATIONS``); the row is
   not, because ``postern_app`` holds ``UPDATE`` on ``challenges`` and the api
   connects as that role.
2. Tier 1 is unchanged: no claim is read.
3. Tier 2 needs four claims of the verified banking-app assertion: ``idv``
   equal to ``POSTERN_CONFIRM_IDV_VALUE``, ``challenge_id`` equal to the
   challenge in the request path, a ``jti`` of 1 to 128 printable ASCII
   characters, and a numeric ``auth_time`` no earlier than 30 seconds before
   the row was created and no later than 30 seconds from now. With the
   setting unset every tier-2 row is refused, ``verification_not_configured``.
4. Any other tier, which in a database whose CHECK allows 0 to 2 means tier 0,
   is refused, ``tier_unsupported``. A tier-0 row of a declared operation
   never gets here: every declared tier is 1 or 2, so step 1 refuses it first.

WHAT THIS PROVES, AND WHAT IT CANNOT. The trust anchor is the operator's app
backend, which minted the assertion: the claims say "identity verification
happened for this challenge", and nothing in this repository can check the
match itself (handoff section 6.3 and section 10.8 place it in the backend
cluster). What it stops is an approval that carries no claim of verification,
and one assertion reused across challenges. It cannot see one verification
backing several assertions, an ``idv`` the backend sets without a
verification, or an ``auth_time`` it sets to whatever it likes; the mobile
app pairing contract lists what the backend must do instead.

`check_tier` is pure: no I/O, no clock, no logging. `tier_refusal` is the
one function here that logs, and it names the failed claim and never a value.
"""

from __future__ import annotations

import logging
import math
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from postern_core.domain.verification import VerificationTier
from postern_core.modules.write import WriteOperation
from postern_core.store.models import ChallengeRecord
from starlette.responses import JSONResponse

from services.confirm.audit import (
    DETAIL_TIER_MISMATCH,
    DETAIL_TIER_UNSUPPORTED,
    DETAIL_VERIFICATION_NOT_CONFIGURED,
    DETAIL_VERIFICATION_REQUIRED,
)
from services.confirm.auth import ASSERTION_CLOCK_SKEW_SECONDS
from services.confirm.settings import is_visible_ascii

logger = logging.getLogger(__name__)

#: The ``error`` codes a refusal answers with. Two tier-2 failures share the
#: first; the audit ``detail`` tells them apart.
VERIFICATION_REQUIRED_ERROR = "verification_required"
TIER_MISMATCH_ERROR = "tier_mismatch"
TIER_UNSUPPORTED_ERROR = "tier_unsupported"

#: The fixed ``error_description`` of each. None names a claim or carries a
#: value: a caller cannot change the signed claims, so there is nothing for it
#: to probe, and the configured value must never be in a response.
VERIFICATION_REQUIRED_DESCRIPTION = (
    "this challenge requires proof of app identity verification, and the assertion "
    "does not carry it"
)
TIER_MISMATCH_DESCRIPTION = (
    "this challenge is stored below the verification tier its operation requires"
)
TIER_UNSUPPORTED_DESCRIPTION = "this challenge's verification tier cannot be approved"

#: The four claims a tier-2 approval reads, by name. The WARNING line names
#: whichever failed.
IDV_CLAIM = "idv"
CHALLENGE_ID_CLAIM = "challenge_id"
JTI_CLAIM = "jti"
AUTH_TIME_CLAIM = "auth_time"


@dataclass(frozen=True, slots=True)
class TierRefusal:
    """Why an approval is refused before the claim.

    ``failed_claim`` names the tier-2 claim that failed, for the operator's
    log line, and is ``None`` for the three refusals that are about the row
    or the setting rather than a claim.
    """

    error: str
    detail: str
    description: str
    failed_claim: str | None


@dataclass(frozen=True, slots=True)
class TierVerdict:
    """What `check_tier` decided.

    ``refusal`` is ``None`` when the approval may go on to the claim.
    ``assertion_jti`` is the assertion's ``jti`` once it has passed its own
    check on a tier-2 row, whether or not a later check refused, so the audit
    row can record it (spec section 8); ``None`` otherwise, and always
    ``None`` on tier 1.
    """

    refusal: TierRefusal | None
    assertion_jti: str | None


_TIER_MISMATCH = TierRefusal(
    error=TIER_MISMATCH_ERROR,
    detail=DETAIL_TIER_MISMATCH,
    description=TIER_MISMATCH_DESCRIPTION,
    failed_claim=None,
)
_TIER_UNSUPPORTED = TierRefusal(
    error=TIER_UNSUPPORTED_ERROR,
    detail=DETAIL_TIER_UNSUPPORTED,
    description=TIER_UNSUPPORTED_DESCRIPTION,
    failed_claim=None,
)
_NOT_CONFIGURED = TierRefusal(
    error=VERIFICATION_REQUIRED_ERROR,
    detail=DETAIL_VERIFICATION_NOT_CONFIGURED,
    description=VERIFICATION_REQUIRED_DESCRIPTION,
    failed_claim=None,
)


def _required(claim: str) -> TierRefusal:
    return TierRefusal(
        error=VERIFICATION_REQUIRED_ERROR,
        detail=DETAIL_VERIFICATION_REQUIRED,
        description=VERIFICATION_REQUIRED_DESCRIPTION,
        failed_claim=claim,
    )


def _auth_time_within(value: object, *, lower: float, upper: float) -> bool:
    """A finite JSON number, not a bool, inside ``[lower, upper]``.

    ``bool`` is refused by name because it is an ``int`` subclass, for the
    reason `services/confirm/auth.py`'s `_is_time` gives. Finiteness is
    checked on a ``float`` only: ``math.isfinite`` raises ``OverflowError``
    on an ``int`` too large for a float (``10**400`` is a valid JSON number),
    and every ``int`` is finite anyway, so the comparison below is exact.
    """
    if isinstance(value, bool) or not isinstance(value, int | float):
        return False
    if isinstance(value, float) and not math.isfinite(value):
        return False
    return lower <= value <= upper


def check_tier(
    *,
    record: ChallengeRecord,
    challenge_id: str,
    claims: Mapping[str, Any],
    expected_idv: str | None,
    now: float,
    operations: Mapping[str, WriteOperation],
) -> TierVerdict:
    """Decide whether this approval may go on to the claim (module docstring).

    Args:
        record: the stored challenge row, as ``get_challenge`` read it.
        challenge_id: the challenge id from the request path.
        claims: every claim of the verified banking-app assertion.
        expected_idv: ``ConfirmSettings.idv_value``; ``None`` when unset.
        now: the current time, seconds since the epoch.
        operations: the declared write operations, keyed by tool name.
    """
    declared = operations.get(record.tool_name)
    if declared is not None and record.tier < declared.tier:
        return TierVerdict(refusal=_TIER_MISMATCH, assertion_jti=None)
    if record.tier == VerificationTier.APP_APPROVAL:
        return TierVerdict(refusal=None, assertion_jti=None)
    if record.tier != VerificationTier.APP_IDENTITY_VERIFICATION:
        return TierVerdict(refusal=_TIER_UNSUPPORTED, assertion_jti=None)
    if expected_idv is None:
        return TierVerdict(refusal=_NOT_CONFIGURED, assertion_jti=None)

    # Exact comparison on the stored string: no case folding, no trimming,
    # no normalisation. `isinstance` first, so a missing or null claim is
    # refused before anything is compared with it.
    idv = claims.get(IDV_CLAIM)
    if not isinstance(idv, str) or idv != expected_idv:
        return TierVerdict(refusal=_required(IDV_CLAIM), assertion_jti=None)

    # Against the PATH, which is the challenge this request is approving.
    bound = claims.get(CHALLENGE_ID_CLAIM)
    if not isinstance(bound, str) or bound != challenge_id:
        return TierVerdict(refusal=_required(CHALLENGE_ID_CLAIM), assertion_jti=None)

    # The character rule is what keeps the claiming UPDATE from raising on a
    # NUL when this value is stored as `verification_result`.
    jti = claims.get(JTI_CLAIM)
    if not isinstance(jti, str) or not is_visible_ascii(jti):
        return TierVerdict(refusal=_required(JTI_CLAIM), assertion_jti=None)

    # From here on the jti is recorded even on a refusal (spec section 8).
    if not _auth_time_within(
        claims.get(AUTH_TIME_CLAIM),
        lower=record.created_at.timestamp() - ASSERTION_CLOCK_SKEW_SECONDS,
        upper=now + ASSERTION_CLOCK_SKEW_SECONDS,
    ):
        return TierVerdict(refusal=_required(AUTH_TIME_CLAIM), assertion_jti=jti)
    return TierVerdict(refusal=None, assertion_jti=jti)


def tier_refusal(challenge_id: str, refusal: TierRefusal) -> tuple[JSONResponse, str]:
    """The 403 and the audit ``detail`` for ``refusal``, with one WARNING line.

    403 and not 401, for the reason ``services/confirm/device_signature.py``
    gives for its own refusals: the caller authenticated and is not permitted.
    The log line names the failed claim, or the refusal's detail when no claim
    failed, and never a claim value or the configured value: an operator needs
    to know which claim to take up with the app backend, and with the payments
    flag on, each refusal has already cost a customer a verification.
    """
    if refusal.failed_claim is None:
        logger.warning("challenge approve: %s refused, %s", challenge_id, refusal.detail)
    else:
        logger.warning(
            "challenge approve: %s refused, the assertion's %s claim does not prove "
            "app identity verification for this challenge",
            challenge_id,
            refusal.failed_claim,
        )
    response = JSONResponse(
        status_code=403,
        content={"error": refusal.error, "error_description": refusal.description},
    )
    return response, refusal.detail
```

The module docstring says the callback calls `check_tier`; Task 4 makes that true. Until then nothing imports this module outside its test.

- [ ] **Step 6: Run it and see it pass**

Run: `uv run pytest -q -rs tests/test_tier_proof.py`
Expected: `46 passed`.

- [ ] **Step 7: Mutations** (each: apply in `services/confirm/tier_proof.py`, run `uv run pytest -q -rs tests/test_tier_proof.py`, expect FAIL, restore the original text)

1. "compare `idv` case-insensitively": replace `idv != expected_idv` with `idv.casefold() != expected_idv.casefold()`. Fails `[idv-other-case]`.
2. "skip the `challenge_id` comparison": replace `if not isinstance(bound, str) or bound != challenge_id:` with `if False:`. Fails the three `challenge-id` cases.
3. "accept a missing `jti`": replace `if not isinstance(jti, str) or not is_visible_ascii(jti):` with `if jti is not None and (not isinstance(jti, str) or not is_visible_ascii(jti)):`. Fails `[jti-missing]`.
4. "drop the `auth_time` lower bound": replace `return lower <= value <= upper` with `return value <= upper`. Fails `[auth-time-31s-before-creation]`.
5. "drop the upper bound": replace `return lower <= value <= upper` with `return lower <= value`. Fails `[auth-time-31s-ahead]`.
6. "accept a bool `auth_time`": replace `if isinstance(value, bool) or not isinstance(value, int | float):` with `if not isinstance(value, int | float):`. Fails `test_a_bool_auth_time_is_refused_where_the_integer_1_would_pass` (with a real creation time, `True` is out of bounds anyway, which is why that test moves the row to one second after the epoch).
7. "drop the `tier_mismatch` check": replace `if declared is not None and record.tier < declared.tier:` with `if False:`. Fails both `test_a_payment_row_below_its_declared_tier_is_a_mismatch` cases and the operations test.
8. "`< 128` for `<= 128`" (in `services/confirm/settings.py`, as in Task 2): fails `test_a_jti_of_exactly_128_characters_passes`.

- [ ] **Step 8: Gates**

Run: `uv run ruff format packages services tests`
Run: `uv run ruff check --fix services/confirm/tier_proof.py services/confirm/audit.py tests/test_tier_proof.py`
Run: `make lint fmt-check type imports citations`
Expected: every gate passes; `lint-imports` reports `Contracts: 7 kept, 0 broken`.
Run: `make tool-surface`
Run: `git diff --exit-code tool-surface.json`
Expected: `tool-surface.json unchanged`, then exit 0.

- [ ] **Step 9: Full suite**

Run: `make ci > /private/tmp/claude-501/-Users-stefano-Projects-postern/dce26918-b575-4415-8de8-976663bf0f78/scratchpad/ci-task3.log 2>&1; echo EXIT=$?`
Expected: `EXIT=0`, `4690 passed`.

- [ ] **Step 10: Commit**

```bash
git add services/confirm/tier_proof.py services/confirm/audit.py tests/test_tier_proof.py
git commit -m "feat(confirm): the tier-2 proof rule as a pure function, and its four audit details" -m "Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>"
```

---

### Task 4: Enforce the tier in `_approve`

Spec sections 6, 7, 8 and 11, and the `verified_claims` docstring.

**Files:**
- Create: `tests/test_tier2_approval.py`
- Modify: `services/confirm/callback.py`, `services/confirm/audit.py`, `services/confirm/auth.py`, `tests/test_payments_approval_path.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/test_tier2_approval.py`:

```python
"""Tier enforcement at approval, through the real confirm app and Postgres.

Spec docs/superpowers/specs/2026-10-06-tier2-approval-enforcement-design.md,
section 11, and decision record 0023. Every approval here carries a valid
device signature over the stored row unless a test says otherwise, so what is
measured is the tier check that sits between that signature and the claim.
`tests/test_tier_proof.py` holds the same rule as a pure function, with the
bounds tested exactly.
"""

import asyncio
import json
import logging
import time
import uuid
from collections.abc import AsyncIterator, Callable
from typing import Any

import httpx2
import pytest
import pytest_asyncio
from fastmcp.server.auth.providers.jwt import JWTVerifier, RSAKeyPair
from postern_core.payments import CREATE_PAYMENT_TOOL
from postern_core.store import challenges as store
from postern_core.store.engine import Database
from postern_core.store.models import AuditEntry, ChallengeRecord
from sqlalchemy import select, text
from starlette.applications import Starlette

from services.confirm.execute import BackendWriteClient
from services.confirm.main import create_confirm_app
from services.confirm.revocation import REVOKED_ERROR
from services.confirm.settings import ConfirmSettings
from services.confirm.tier_proof import (
    TIER_MISMATCH_DESCRIPTION,
    TIER_UNSUPPORTED_DESCRIPTION,
    VERIFICATION_REQUIRED_DESCRIPTION,
)
from tests.fixtures.device_keys import device_key, enrolled_store, sign_row

ISSUER = "https://app.test.invalid"
AUDIENCE = "postern-confirm"
OWNER = "cust_tier2owner"
OTHER = "cust_tier2other"
IDV = "postern-dev-idv"
TIER_1_TOOL = "standing_orders.cancel"
PAYLOAD: dict[str, Any] = {
    "from_account_ref": "acc_tier2",
    "payee_ref": "payee_tier2",
    "payee_name": "Northwind Energy",
    "amount": "10.00",
    "currency": "EUR",
    "reference": "Rent October",
}
TIER_1_PAYLOAD: dict[str, Any] = {"order_id": "so_tier2"}
#: A string no refusal may echo, in a response, an audit row or a log line.
SENTINEL = "SENTINEL-claim-value"

DEVICE_PRIVATE, DEVICE_PUBLIC = device_key("tier2-phone")
OTHER_PRIVATE, OTHER_PUBLIC = device_key("tier2-other-phone")


@pytest.fixture(scope="module")
def key_pair() -> RSAKeyPair:
    return RSAKeyPair.generate()


@pytest_asyncio.fixture
async def db(database: Database) -> AsyncIterator[Database]:
    """The session-scoped database, with this module's challenges deleted after."""
    yield database
    async with database.sessionmaker() as s:
        await s.execute(text("DELETE FROM challenges WHERE challenge_id LIKE 't2_%'"))
        await s.commit()


@pytest.fixture()
def sent(monkeypatch: pytest.MonkeyPatch) -> list[httpx2.Request]:
    """Every request the executor sends; the backend accepts each."""
    calls: list[httpx2.Request] = []

    def backend(request: httpx2.Request) -> httpx2.Response:
        calls.append(request)
        return httpx2.Response(200, json={"status": "accepted"})

    original = BackendWriteClient.__init__

    def patched(self: Any, *args: Any, **kwargs: Any) -> None:
        original(self, *args, transport=httpx2.MockTransport(backend), **kwargs)

    monkeypatch.setattr(BackendWriteClient, "__init__", patched)
    return calls


def build_app(pg_url: str, key_pair: RSAKeyPair, *, idv_value: str | None = IDV) -> Starlette:
    settings = ConfirmSettings(
        backend_base_url="https://backend.test",
        database_url=pg_url,
        allow_non_uri_audience=True,
        allow_process_local_sessions=True,
        idv_value=idv_value,
    )
    return create_confirm_app(
        settings,
        assertion_verifier=JWTVerifier(
            public_key=key_pair.public_key, issuer=ISSUER, audience=AUDIENCE
        ),
        device_key_store=enrolled_store(OWNER, DEVICE_PUBLIC, **{OTHER: (OTHER_PUBLIC,)}),
    )


@pytest.fixture()
def app(pg_url: str, key_pair: RSAKeyPair) -> Starlette:
    return build_app(pg_url, key_pair)


#: Maps the digits of a uuid4 hex to letters. A hex id carries a twelve-digit
#: run or a letter-letter-digit-digit opener often enough for the audit scrub
#: to mask part of it (the producer plan's masking note), and these tests find
#: their audit rows by the recorded `challenge_id`, so the ids carry no digit
#: after the prefix.
_DIGITS_TO_LETTERS = str.maketrans("0123456789", "ghijklmnop")


def new_challenge_id() -> str:
    return f"t2_{uuid.uuid4().hex.translate(_DIGITS_TO_LETTERS)}"


async def seed(
    db: Database,
    *,
    tier: int = 2,
    tool_name: str = CREATE_PAYMENT_TOOL,
    customer_ref: str = OWNER,
    payload: dict[str, Any] | None = None,
) -> ChallengeRecord:
    """One pending challenge, committed so the app's own pool sees it."""
    async with db.sessionmaker() as s:
        record = await store.create_challenge(
            s,
            challenge_id=new_challenge_id(),
            customer_ref=customer_ref,
            tool_name=tool_name,
            payload=dict(payload if payload is not None else PAYLOAD),
            tier=tier,
        )
        await s.commit()
    return record


def tier2_claims(record: ChallengeRecord, **overrides: Any) -> dict[str, Any]:
    """The four claims, valid for ``record`` unless overridden."""
    claims: dict[str, Any] = {
        "idv": IDV,
        "challenge_id": record.challenge_id,
        "jti": f"jti-{uuid.uuid4().hex}",
        "auth_time": record.created_at.timestamp(),
    }
    claims.update(overrides)
    return claims


def bearer(
    key_pair: RSAKeyPair, claims: dict[str, Any] | None = None, *, subject: str = OWNER
) -> dict[str, str]:
    token = key_pair.create_token(
        subject=subject,
        issuer=ISSUER,
        audience=AUDIENCE,
        expires_in_seconds=60,
        additional_claims=claims or None,
    )
    return {"Authorization": f"Bearer {token}"}


async def approve(
    app: Starlette,
    record: ChallengeRecord,
    headers: dict[str, str],
    *,
    signer: Any = DEVICE_PRIVATE,
    **extra: Any,
) -> httpx2.Response:
    body = {"signature": sign_row(signer, record), **extra}
    async with httpx2.AsyncClient(
        transport=httpx2.ASGITransport(app=app), base_url="http://t"
    ) as client:
        return await client.post(
            f"/challenges/{record.challenge_id}/approve", json=body, headers=headers
        )


async def stored(db: Database, challenge_id: str) -> ChallengeRecord:
    async with db.sessionmaker() as s:
        row = await store.get_challenge(s, challenge_id)
    assert row is not None
    return row


async def audit_rows(db: Database, challenge_id: str) -> list[AuditEntry]:
    async with db.sessionmaker() as s:
        result = await s.execute(select(AuditEntry).order_by(AuditEntry.id))
        entries = list(result.scalars().all())
    return [e for e in entries if e.arguments.get("challenge_id") == challenge_id]


# -- The happy path ------------------------------------------------------------------


async def test_a_tier_2_approval_with_all_four_claims_executes_and_stores_the_jti(
    app: Starlette, db: Database, key_pair: RSAKeyPair, sent: list[httpx2.Request]
) -> None:
    record = await seed(db)
    claims = tier2_claims(record, jti="jti-happy-path-0001")
    response = await approve(
        app, record, bearer(key_pair, claims), verification_result="body-chosen-string"
    )
    assert response.status_code == 200, response.text
    assert len(sent) == 1
    row = await stored(db, record.challenge_id)
    assert row.status == "executed"
    assert row.verification_result == "jti-happy-path-0001"
    entries = await audit_rows(db, record.challenge_id)
    assert [e.outcome for e in entries] == ["reaching", "returned"]
    assert all(e.arguments["assertion_jti"] == "jti-happy-path-0001" for e in entries)
    # The scrubbed body is still recorded, and is not what the row stores.
    assert all(e.arguments["verification_result"] == "body-chosen-string" for e in entries)


@pytest.mark.parametrize("case", ["jti-128", "auth-time-lower-bound", "auth-time-upper-bound"])
async def test_the_boundary_values_are_accepted(
    case: str, app: Starlette, db: Database, key_pair: RSAKeyPair, sent: list[httpx2.Request]
) -> None:
    """The upper bound is minted against this process's clock just before the
    request, so it sits within the request's own latency of the bound;
    `tests/test_tier_proof.py` tests both bounds exactly."""
    record = await seed(db)
    cases: dict[str, dict[str, Any]] = {
        "jti-128": {"jti": "j" * 128},
        "auth-time-lower-bound": {"auth_time": record.created_at.timestamp() - 30},
        "auth-time-upper-bound": {"auth_time": time.time() + 30},
    }
    claims = tier2_claims(record, **cases[case])
    response = await approve(app, record, bearer(key_pair, claims))
    assert response.status_code == 200, response.text
    assert len(sent) == 1


# -- Each claim refused -------------------------------------------------------------

Claims = Callable[[ChallengeRecord], dict[str, Any]]


def _drop(name: str) -> Claims:
    def build(record: ChallengeRecord) -> dict[str, Any]:
        claims = tier2_claims(record)
        del claims[name]
        return claims

    return build


def _set(**overrides: Any) -> Claims:
    return lambda record: tier2_claims(record, **overrides)


REFUSED: list[Any] = [
    pytest.param(_drop("idv"), False, id="idv-missing"),
    pytest.param(_set(idv=1), False, id="idv-not-a-string"),
    pytest.param(_set(idv=SENTINEL), False, id="idv-wrong"),
    pytest.param(_set(idv=IDV.upper()), False, id="idv-other-case"),
    pytest.param(_set(idv=""), False, id="idv-empty"),
    pytest.param(_set(idv=None), False, id="idv-null"),
    pytest.param(_drop("challenge_id"), False, id="challenge-id-missing"),
    pytest.param(_set(challenge_id=7), False, id="challenge-id-number"),
    pytest.param(_set(challenge_id=SENTINEL), False, id="challenge-id-wrong"),
    pytest.param(_drop("jti"), False, id="jti-missing"),
    pytest.param(_set(jti=7), False, id="jti-number"),
    pytest.param(_set(jti=""), False, id="jti-empty"),
    pytest.param(_set(jti="j" * 129), False, id="jti-129-characters"),
    pytest.param(_set(jti=f"{SENTINEL}\x00"), False, id="jti-nul"),
    pytest.param(_set(jti=f"{SENTINEL} x"), False, id="jti-space"),
    pytest.param(_drop("auth_time"), True, id="auth-time-missing"),
    pytest.param(_set(auth_time=True), True, id="auth-time-bool"),
    pytest.param(_set(auth_time=SENTINEL), True, id="auth-time-string"),
    pytest.param(_set(auth_time=float("nan")), True, id="auth-time-nan"),
    pytest.param(_set(auth_time=float("inf")), True, id="auth-time-inf"),
    pytest.param(
        lambda record: tier2_claims(record, auth_time=record.created_at.timestamp() - 31),
        True,
        id="auth-time-31s-before-creation",
    ),
    pytest.param(
        lambda record: tier2_claims(record, auth_time=time.time() + 31),
        True,
        id="auth-time-31s-ahead",
    ),
]


@pytest.mark.parametrize(("build_claims", "jti_recorded"), REFUSED)
async def test_each_failed_claim_is_refused_and_the_row_stays_pending(
    build_claims: Claims,
    jti_recorded: bool,
    app: Starlette,
    db: Database,
    key_pair: RSAKeyPair,
    sent: list[httpx2.Request],
    caplog: pytest.LogCaptureFixture,
) -> None:
    record = await seed(db)
    claims = build_claims(record)
    with caplog.at_level(logging.WARNING, logger="services.confirm.tier_proof"):
        response = await approve(app, record, bearer(key_pair, claims))
    assert response.status_code == 403, response.text
    assert response.json() == {
        "error": "verification_required",
        "error_description": VERIFICATION_REQUIRED_DESCRIPTION,
    }
    assert (await stored(db, record.challenge_id)).status == "pending"
    assert sent == []
    (row,) = await audit_rows(db, record.challenge_id)
    assert (row.outcome, row.detail) == ("raised", "verification_required")
    assert ("assertion_jti" in row.arguments) is jti_recorded
    # Neither the configured value nor a claim value reaches anything a
    # caller or an operator reads; the log line names a claim, not a value.
    for where in (response.text, json.dumps(row.arguments), caplog.text):
        assert SENTINEL not in where
        assert IDV not in where
    (logged,) = [r for r in caplog.records if r.name == "services.confirm.tier_proof"]
    assert record.challenge_id in logged.getMessage()
    assert "claim does not prove" in logged.getMessage()


async def test_an_assertion_minted_for_one_challenge_does_not_approve_another(
    app: Starlette, db: Database, key_pair: RSAKeyPair, sent: list[httpx2.Request]
) -> None:
    first = await seed(db)
    second = await seed(db)
    response = await approve(app, second, bearer(key_pair, tier2_claims(first)))
    assert response.status_code == 403, response.text
    assert response.json()["error"] == "verification_required"
    assert (await stored(db, second.challenge_id)).status == "pending"
    assert (await stored(db, first.challenge_id)).status == "pending"
    assert sent == []


# -- The setting ---------------------------------------------------------------------


async def test_unset_refuses_tier_2_and_still_approves_tier_1(
    pg_url: str, db: Database, key_pair: RSAKeyPair, sent: list[httpx2.Request]
) -> None:
    app = build_app(pg_url, key_pair, idv_value=None)
    tier_2 = await seed(db)
    refused = await approve(app, tier_2, bearer(key_pair, tier2_claims(tier_2)))
    assert refused.status_code == 403, refused.text
    assert refused.json() == {
        "error": "verification_required",
        "error_description": VERIFICATION_REQUIRED_DESCRIPTION,
    }
    (row,) = await audit_rows(db, tier_2.challenge_id)
    assert row.detail == "verification_not_configured"
    assert (await stored(db, tier_2.challenge_id)).status == "pending"

    tier_1 = await seed(db, tier=1, tool_name=TIER_1_TOOL, payload=TIER_1_PAYLOAD)
    approved = await approve(app, tier_1, bearer(key_pair))
    assert approved.status_code == 200, approved.text
    assert len(sent) == 1


# -- Tier 1, tier 0 and the declared tier --------------------------------------------


@pytest.mark.parametrize("with_claims", [False, True], ids=["no-claims", "extra-claims"])
async def test_a_tier_1_row_is_approved_as_before(
    with_claims: bool,
    app: Starlette,
    db: Database,
    key_pair: RSAKeyPair,
    sent: list[httpx2.Request],
) -> None:
    record = await seed(db, tier=1, tool_name=TIER_1_TOOL, payload=TIER_1_PAYLOAD)
    claims = tier2_claims(record) if with_claims else None
    response = await approve(
        app, record, bearer(key_pair, claims), verification_result="selfie-ref-0001"
    )
    assert response.status_code == 200, response.text
    assert len(sent) == 1
    assert (await stored(db, record.challenge_id)).verification_result == "selfie-ref-0001"
    entries = await audit_rows(db, record.challenge_id)
    assert all("assertion_jti" not in e.arguments for e in entries)


async def test_a_tier_0_row_is_refused_as_unsupported(
    app: Starlette, db: Database, key_pair: RSAKeyPair, sent: list[httpx2.Request]
) -> None:
    """Of an operation confirm does not declare: a tier-0 row of a declared one
    is refused as a mismatch first (`tests/test_tier_proof.py`)."""
    record = await seed(db, tier=0, tool_name="test.unregistered_write")
    response = await approve(app, record, bearer(key_pair, tier2_claims(record)))
    assert response.status_code == 403, response.text
    assert response.json() == {
        "error": "tier_unsupported",
        "error_description": TIER_UNSUPPORTED_DESCRIPTION,
    }
    assert (await stored(db, record.challenge_id)).status == "pending"
    (row,) = await audit_rows(db, record.challenge_id)
    assert row.detail == "tier_unsupported"
    assert sent == []


async def test_a_payment_row_stored_at_tier_1_is_a_mismatch(
    app: Starlette, db: Database, key_pair: RSAKeyPair, sent: list[httpx2.Request]
) -> None:
    """What an api compromise holding `postern_app` could write: a payment the
    customer would approve with a device signature alone."""
    record = await seed(db, tier=1)
    response = await approve(app, record, bearer(key_pair))
    assert response.status_code == 403, response.text
    assert response.json() == {
        "error": "tier_mismatch",
        "error_description": TIER_MISMATCH_DESCRIPTION,
    }
    assert (await stored(db, record.challenge_id)).status == "pending"
    (row,) = await audit_rows(db, record.challenge_id)
    assert row.detail == "tier_mismatch"
    assert sent == []


# -- Order: the tier check runs after the signature and the ownership checks ---------


async def test_the_signature_is_checked_before_the_tier(
    app: Starlette, db: Database, key_pair: RSAKeyPair, sent: list[httpx2.Request]
) -> None:
    """A wrong device signature and the claims MISSING: the signature answers."""
    record = await seed(db)
    response = await approve(app, record, bearer(key_pair), signer=OTHER_PRIVATE)
    assert response.status_code == 403, response.text
    assert response.json()["error"] == "invalid_signature"
    assert (await stored(db, record.challenge_id)).status == "pending"
    assert sent == []


async def test_ownership_is_checked_before_the_tier(
    app: Starlette, db: Database, key_pair: RSAKeyPair, sent: list[httpx2.Request]
) -> None:
    """Another customer's tier-2 challenge and NO claims: the byte-identical
    404 every unknown id gets, and the table tells the two apart."""
    record = await seed(db, customer_ref=OTHER)
    response = await approve(app, record, bearer(key_pair))
    assert response.status_code == 404, response.text
    assert response.json() == {
        "error": "not_found",
        "error_description": f"challenge {record.challenge_id} not found",
    }
    (row,) = await audit_rows(db, record.challenge_id)
    assert row.detail == "challenge_not_owned"
    assert (await stored(db, record.challenge_id)).status == "pending"
    assert sent == []


async def test_a_revoked_customer_is_refused_as_revoked_even_with_valid_claims(
    app: Starlette, db: Database, key_pair: RSAKeyPair, sent: list[httpx2.Request]
) -> None:
    record = await seed(db)
    await app.state.postern_revocation_store.revoke_customer_client(
        customer_ref=OWNER, client_id="any-client"
    )
    response = await approve(app, record, bearer(key_pair, tier2_claims(record)))
    assert response.status_code == 403, response.text
    assert response.json()["error"] == REVOKED_ERROR
    (row,) = await audit_rows(db, record.challenge_id)
    assert row.detail == "revoked"
    assert sent == []


# -- Retry and concurrency ---------------------------------------------------------


async def test_a_refusal_leaves_the_row_approvable_inside_its_window(
    app: Starlette, db: Database, key_pair: RSAKeyPair, sent: list[httpx2.Request]
) -> None:
    record = await seed(db)
    first = await approve(app, record, bearer(key_pair, _drop("idv")(record)))
    assert first.status_code == 403, first.text
    second = await approve(app, record, bearer(key_pair, tier2_claims(record)))
    assert second.status_code == 200, second.text
    assert len(sent) == 1


async def test_a_valid_and_an_invalid_approval_race_and_only_the_valid_one_executes(
    app: Starlette, db: Database, key_pair: RSAKeyPair, sent: list[httpx2.Request]
) -> None:
    record = await seed(db)
    valid, invalid = await asyncio.gather(
        approve(app, record, bearer(key_pair, tier2_claims(record))),
        approve(app, record, bearer(key_pair, _drop("jti")(record))),
    )
    assert valid.status_code == 200, valid.text
    assert invalid.status_code == 403, invalid.text
    assert invalid.json()["error"] == "verification_required"
    assert len(sent) == 1
    assert (await stored(db, record.challenge_id)).status == "executed"
```

In `tests/test_payments_approval_path.py`, make these six replacements.

Replace

```python
CONFIRM_AUDIENCE = "postern-confirm"
```

with

```python
CONFIRM_AUDIENCE = "postern-confirm"
#: The `idv` value this confirm app requires of a tier-2 approval (decision 0023).
IDV_VALUE = "postern-test-idv"
```

Replace

```python
        allow_process_local_sessions=True,
    )
    verifier = JWTVerifier(
```

with

```python
        allow_process_local_sessions=True,
        idv_value=IDV_VALUE,
    )
    verifier = JWTVerifier(
```

Replace

```python
    payload. Tier 2 is not enforced at approval yet (spec section 2), which is
    why a signature alone suffices here."""
```

with

```python
    payload. The row is tier 2, so the assertion carries the four claims
    decision record 0023 requires, and the row stores the assertion's jti as
    its verification_result."""
```

Replace

```python
    # Confirm does not read the tier yet; this pins the stored value for when
    # enforcement lands.
    assert row.tier == PAYMENT_TIER
```

with

```python
    # The tier the callback enforces below.
    assert row.tier == PAYMENT_TIER
```

Replace

```python
    assertion = key_pair.create_token(
        subject=OWNER, issuer=CONFIRM_ISSUER, audience=CONFIRM_AUDIENCE, expires_in_seconds=60
    )
```

with

```python
    jti = "producer-approval-0001"
    assertion = key_pair.create_token(
        subject=OWNER,
        issuer=CONFIRM_ISSUER,
        audience=CONFIRM_AUDIENCE,
        expires_in_seconds=60,
        additional_claims={
            "idv": IDV_VALUE,
            "challenge_id": challenge_id,
            "jti": jti,
            "auth_time": row.created_at.timestamp(),
        },
    )
```

Replace

```python
    status = await payment_status(produced)(challenge_id=challenge_id)
    assert status["status"] == "executed"
```

with

```python
    status = await payment_status(produced)(challenge_id=challenge_id)
    assert status["status"] == "executed"
    async with produced.sessionmaker() as s:
        final = await store.get_challenge(s, challenge_id)
    assert final is not None
    assert final.verification_result == jti
```

- [ ] **Step 2: Run them and see them fail**

Run: `uv run pytest -q -rs tests/test_tier2_approval.py tests/test_payments_approval_path.py`
Expected: FAIL. The happy path fails with `AssertionError: assert 'body-chosen-string' == 'jti-happy-path-0001'`; every refusal case, the A-for-B test, the unset test, the tier-0 test and the mismatch test fail with `assert 200 == 403` (the callback approves them today); `test_a_produced_challenge_is_approved_and_executes_the_stored_payload` fails on `assert None == 'producer-approval-0001'`. The tier-1 tests, the signature-first, ownership-first and revoked tests already pass: they pin an order that the mutations in Step 6 break.

- [ ] **Step 3: Record the `jti` in the audit row**

In `services/confirm/audit.py`, replace

```python
from postern_core.store.audit import TRUNCATED, bound_arguments, clamp
```

with

```python
from postern_core.store.audit import ARGUMENTS_TRUNCATED_KEY, TRUNCATED, bound_arguments, clamp
```

Replace

```python
        self._tool_name = scrub_text(tool_name)
```

with

```python
        self._tool_name = scrub_text(tool_name)

    def note_assertion_jti(self, jti: str) -> None:
        """Record the tier-2 assertion's ``jti`` in this request's ``arguments``.

        Called by ``services/confirm/callback.py`` once the ``jti`` has passed
        its check on a tier-2 row, whether the approval then succeeds or is
        refused (spec docs/superpowers/specs/2026-10-06-tier2-approval-enforcement-design.md,
        section 8). Both rows written after it carry the value. The
        ``challenges`` row stores the same ``jti`` as ``verification_result``
        on success, but ``postern_app`` holds ``UPDATE`` on that table, so this
        append-only copy is the one of record.

        Scrubbed outside the request's ``redaction_budget`` scope, for the
        reason `resolve` gives: the value is at most 128 printable ASCII
        characters by the time it gets here, so the fresh allowance it gets
        cannot be spent to any degree that matters.
        """
        self._arguments = _with_assertion_jti(self._arguments, scrub_text(jti))
```

Replace

```python
            "verification_result": scrub_tree(body.get("verification_result")),
        }
    )
```

with

```python
            "verification_result": scrub_tree(body.get("verification_result")),
        }
    )


#: The three server-chosen keys `_arguments` lists first, in its order.
_SERVER_CHOSEN_KEYS = ("route", "challenge_id", "signature_present")

#: Where `ApprovalAudit.note_assertion_jti` records a tier-2 assertion's ``jti``.
ASSERTION_JTI_ARGUMENT = "assertion_jti"


def _with_assertion_jti(arguments: dict[str, Any], jti: str) -> dict[str, Any]:
    """``arguments`` with ``jti`` added right after the server-chosen keys.

    THE POSITION IS THE FIRST-FIT RULE `_arguments` documents: the ``jti`` is
    validated and short, so it goes ahead of the two caller-supplied fields a
    capped tree drops, and an attack that fills those cannot take it with
    them.

    Bounded again with `bound_arguments` when the tree was not yet capped, so
    adding the value cannot carry a tree past ``MAX_ARGUMENTS_BYTES``
    unmarked. A tree already carrying the truncation marker is not re-capped:
    its marker describes the body as it arrived, and re-capping would replace
    that with a description of the capped tree. The overshoot is the ``jti``
    entry alone, about 150 bytes at most.
    """
    head = {key: value for key, value in arguments.items() if key in _SERVER_CHOSEN_KEYS}
    tail = {key: value for key, value in arguments.items() if key not in _SERVER_CHOSEN_KEYS}
    merged = {**head, ASSERTION_JTI_ARGUMENT: jti, **tail}
    if ARGUMENTS_TRUNCATED_KEY in arguments:
        return merged
    return bound_arguments(merged)
```

- [ ] **Step 4: Wire the check into `_approve`**

In `services/confirm/callback.py`, replace

```python
from services.confirm.execute import BackendWriteClient, BackendWriteError, resolve_endpoint
from services.confirm.revocation import customer_revoked, log_refusal, revoked_response
```

with

```python
from services.confirm.execute import (
    WRITE_OPERATIONS,
    BackendWriteClient,
    BackendWriteError,
    resolve_endpoint,
)
from services.confirm.revocation import customer_revoked, log_refusal, revoked_response
from services.confirm.tier_proof import check_tier, tier_refusal
```

Replace (lines 536 to 539 at b05d406: the end of step 2b and the head of step 3)

```python
        if refusal is not None:
            return refusal

        # --- 3. Claim the challenge: pending -> approved, in one statement ---
```

with

```python
        if refusal is not None:
            return refusal

        # --- 2c. Does the assertion prove what the row's tier requires? ---
        #
        # AFTER the signature and BEFORE the claim, for the two reasons the
        # signature check gives for its own position: a caller who cannot
        # sign learns nothing here about the row's tier, and a refusal leaves
        # the row exactly `pending`, since nothing in this session has
        # written yet. `services/confirm/tier_proof.py` holds the rule
        # (decision record 0023). The tier is read off the stored row and
        # checked against the tier its operation DECLARES, because the row is
        # writable by `postern_app` and the declaration is not.
        verdict = check_tier(
            record=challenge_record,
            challenge_id=challenge_id,
            claims=verified_claims(request),
            expected_idv=request.app.state.settings.idv_value,
            now=time.time(),
            operations=WRITE_OPERATIONS,
        )
        if verdict.assertion_jti is not None:
            audit.note_assertion_jti(verdict.assertion_jti)
        if verdict.refusal is not None:
            return tier_refusal(challenge_id, verdict.refusal)
        # Tier 2 stores the assertion's `jti`, never the body's string: what
        # lands on the row is then the identifier of an assertion that carried
        # the configured `idv` and this challenge's id. Tier 1 is unchanged.
        stored_verification_result = (
            verification_result if verdict.assertion_jti is None else verdict.assertion_jti
        )

        # --- 3. Claim the challenge: pending -> approved, in one statement ---
```

Replace

```python
                confirming_device=body.get("confirming_device"),
                verification_result=verification_result,
```

with

```python
                confirming_device=body.get("confirming_device"),
                verification_result=stored_verification_result,
```

- [ ] **Step 5: `verified_claims` says which claims decide something**

In `services/confirm/auth.py`, replace

```
    ``verified_subject`` returns ``None`` so a handler can fail closed on it;
    this one returns an EMPTY DICT, because no claim it carries is ever an
    authorization input. Its one reader is
    ``services/confirm/audit.py::_client_id``, which asks for ``client_id``
    then ``azp`` to record WHICH client called, and a missing claim there is a
    NULL column, not a refusal.

    Returning ``{}`` rather than ``None`` therefore keeps that reader from
    having to decide what an absent assertion means: on this service it cannot
    happen except in the same handler-without-middleware case
    ``verified_subject`` already fails closed on, and that branch returns 401
    before anything asks for claims.
```

with

```
    ``verified_subject`` returns ``None`` so a handler can fail closed on it;
    this one returns an EMPTY DICT, and both of its readers are safe with one.

    ``services/confirm/audit.py::_client_id`` asks for ``client_id`` then
    ``azp`` to record WHICH client called, and a missing claim there is a NULL
    column, not a refusal.

    The approval callback's tier check (decision record 0023) is the other
    reader, and for it FOUR CLAIMS ARE AUTHORIZATION INPUTS on a tier-2 row:
    ``idv``, ``challenge_id``, ``jti`` and ``auth_time``. Each is tested with
    ``isinstance`` before it is compared, so a claim that is absent, and an
    empty dict as a whole, is a refusal there and never a pass. No other claim
    decides anything; ``sub`` reaches handlers through ``verified_subject``.

    Returning ``{}`` rather than ``None`` therefore keeps neither reader
    deciding what an absent assertion means: on this service it cannot happen
    except in the same handler-without-middleware case ``verified_subject``
    already fails closed on, and that branch returns 401 before anything asks
    for claims.
```

- [ ] **Step 6: Run them and see them pass**

Run: `uv run pytest -q -rs tests/test_tier2_approval.py tests/test_payments_approval_path.py tests/test_tier_proof.py tests/test_callback.py tests/test_write_audit.py tests/test_write_audit_arguments_cap.py tests/test_approval_integration.py tests/test_device_signature.py`
Expected: PASS; `tests/test_tier2_approval.py` contributes 37 tests.

- [ ] **Step 7: Mutations** (each: apply, run the command, expect FAIL, restore with the reverse edit)

1. "skip the tier check": in `services/confirm/callback.py` delete the two lines `        if verdict.refusal is not None:` and `            return tier_refusal(challenge_id, verdict.refusal)`. Run `uv run pytest -q -rs tests/test_tier2_approval.py`. Fails every refusal test.
2. "store the body string for tier 2": in `services/confirm/callback.py` replace `verification_result=stored_verification_result,` with `verification_result=verification_result,`. Run `uv run pytest -q -rs tests/test_tier2_approval.py tests/test_payments_approval_path.py`. Fails the happy path (`'body-chosen-string' == 'jti-happy-path-0001'`) and the producer approval (`None == 'producer-approval-0001'`).
3. "move the tier check above the ownership check": cut the whole step 2c block (from `        # --- 2c. Does the assertion prove` up to, not including, `        # --- 3. Claim the challenge`) and paste it immediately above `        # --- 2. The challenge must belong to the authenticated customer ---`. Run `uv run pytest -q -rs tests/test_tier2_approval.py -k ownership`. Fails: 403 `verification_required` where the byte-identical 404 was expected.
4. "move it above the signature check": cut the same block and paste it immediately above `        refusal = await signature_refusal(`. Run `uv run pytest -q -rs tests/test_tier2_approval.py -k signature_is_checked`. Fails: `verification_required` where `invalid_signature` was expected.
5. "skip the `challenge_id` comparison" (Task 3, mutation 2) and "drop the `tier_mismatch` check" (Task 3, mutation 7): apply each in `services/confirm/tier_proof.py` and run `uv run pytest -q -rs tests/test_tier2_approval.py -k "another or mismatch or challenge-id"`. Each fails through the real callback too.

The spec lists twelve mutations; Tasks 2 to 4 cover all twelve (the self-review maps each).

- [ ] **Step 8: Gates**

Run: `uv run ruff format packages services tests`
Run: `uv run ruff check --fix services/confirm/callback.py services/confirm/audit.py services/confirm/auth.py tests/test_tier2_approval.py tests/test_payments_approval_path.py`
Run: `make lint fmt-check type imports citations`
Expected: every gate passes.
Run: `make tool-surface`
Run: `git diff --exit-code tool-surface.json`
Expected: `tool-surface.json unchanged`, then exit 0.

- [ ] **Step 9: Full suite**

Run: `make ci > /private/tmp/claude-501/-Users-stefano-Projects-postern/dce26918-b575-4415-8de8-976663bf0f78/scratchpad/ci-task4.log 2>&1; echo EXIT=$?`
Expected: `EXIT=0`, `4727 passed`.

- [ ] **Step 10: Commit**

```bash
git add services/confirm/callback.py services/confirm/audit.py services/confirm/auth.py tests/test_tier2_approval.py tests/test_payments_approval_path.py
git commit -m "feat(confirm): enforce the challenge tier at approval; tier 2 needs the idv proof" -m "Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>"
```

---

### Task 5: Documentation, comments and the measured tally

Spec section 12, and section 9 (the contract). No behaviour changes; Steps 1 to 10 are one commit, Steps 11 to 13 a second, tiny one.

**Files:**
- Modify: `CLAUDE.md`, `docs/user-guide/getting-started.md`, `docs/superpowers/specs/2026-10-04-payments-producer-core-design.md`, `services/confirm/execute.py`, `services/confirm/callback.py`, `packages/postern-core/src/postern_core/store/challenges.py`, `packages/postern-core/src/postern_core/store/models.py`, `packages/postern-core/src/postern_core/domain/verification.py`, `docs/user-guide/components/confirm-service.md`, `docs/integration/mobile-app-pairing-contract.md`

- [ ] **Step 1: CLAUDE.md, "What does not" (line 13)**

Replace

```
; nothing delivers a challenge to a phone (handoff section 10.4); and approval does not enforce a challenge's tier, so tier-2 identity verification is not enforced at approval. So the flag stays off in production until all three exist (operator item 12).
```

with

```
; and nothing delivers a challenge to a phone (handoff section 10.4). So the flag stays off in production until both exist (operator item 12). Approval enforces the row's tier since 6 October 2026 (decision record 0023): a row below its operation's declared tier is refused, and a tier-2 row is approved only when the banking-app assertion carries `idv` equal to `POSTERN_CONFIRM_IDV_VALUE`, this challenge's `challenge_id`, a `jti` and an `auth_time` no earlier than the challenge; the row then stores that `jti` as `verification_result`. The trust anchor is the operator's app backend saying a verification happened, which nothing in this repository can check (operator item 13).
```

- [ ] **Step 2: CLAUDE.md, operator item 12 (line 128)**

Replace

```
Turn it on only when all three hold: the approval path enforces a challenge's tier, including `verification_result` for tier 2 (today `services/confirm/callback.py` does not read the row's tier, so a tier-2 payment can be approved on a device signature alone); a delivery path
```

with

```
Turn it on only when both hold, and after item 13: a delivery path
```

- [ ] **Step 3: CLAUDE.md, operator item 13**

Replace

```

---

## Source documents, in reading order
```

with

```

### 13. Tier-2 approval proof (`POSTERN_CONFIRM_IDV_VALUE`)
- **Set `POSTERN_CONFIRM_IDV_VALUE` on `services/confirm`** to a value agreed with your banking-app backend: 1 to 128 printable ASCII characters, emitted in no other claim. Unset, confirm starts with one warning and refuses every tier-2 approval (`verification_required`); every payment is tier 2, so that is every payment.
- **Make your app backend meet the contract** in `docs/integration/mobile-app-pairing-contract.md` section 12: for a tier-2 approval, the assertion carries `idv`, `challenge_id`, a unique `jti` and `auth_time`, set only from the backend's own record of an identity verification that completed for that challenge and that customer, never from the app and never from the login session, and at most one assertion per verification.
- **Know what it does not prove.** Confirm checks that those claims are present and consistent; it cannot check that the selfie match happened, that it happened after the challenge, or that one verification backs only one assertion. A compromised app backend or a stolen assertion-signing key mints the claims for any challenge. Decision record 0023 records that trade, and a signed attestation from the identity-verification service is the stronger form it leaves open.
- **Alert on `audit_log.detail = 'tier_mismatch'`.** No path in this repository writes a row below its operation's declared tier, so one is what a compromise of a process holding `postern_app` leaves behind.

---

## Source documents, in reading order
```

- [ ] **Step 4: Getting started, the flag row (line 100)**

In `docs/user-guide/getting-started.md`, replace

```
Keep it off in production until approval enforces tier 2, a delivery path to the phone exists and `payments` consent can be granted.
```

with

```
Keep it off in production until a delivery path to the phone exists and `payments` consent can be granted. Every payment is tier 2, so `services/confirm` also needs `POSTERN_CONFIRM_IDV_VALUE`.
```

- [ ] **Step 5: The producer spec (lines 16, 32, 203, 215)**

In `docs/superpowers/specs/2026-10-04-payments-producer-core-design.md`, replace

```
| A separate slice in `services/confirm` |
```

with

```
| A separate slice in `services/confirm`, done on 6 October 2026: `docs/superpowers/specs/2026-10-06-tier2-approval-enforcement-design.md` |
```

Replace

```
until tier-2 enforcement lands |
```

with

```
until tier-2 enforcement lands (it landed on 6 October 2026, `docs/superpowers/specs/2026-10-06-tier2-approval-enforcement-design.md`) |
```

Replace

```
1. The approval path enforces the row's tier, including `verification_result` for tier 2.
```

with

```
1. The approval path enforces the row's tier, including `verification_result` for tier 2. Done on 6 October 2026 (`docs/superpowers/specs/2026-10-06-tier2-approval-enforcement-design.md`, decision record 0023).
```

Replace

```
| Tier-2 enforcement at approval | `services/confirm` |
```

with

```
| Tier-2 enforcement at approval | `services/confirm`; done on 6 October 2026 (`docs/superpowers/specs/2026-10-06-tier2-approval-enforcement-design.md`) |
```

- [ ] **Step 6: Code comments (spec section 12)**

In `services/confirm/execute.py` (lines 102 to 103), replace

```
# row it creates, when `POSTERN_PAYMENTS_ENABLED` is on; nothing in
# `services/confirm` reads the tier.
```

with

```
# row it creates, when `POSTERN_PAYMENTS_ENABLED` is on. The approval callback
# reads the declared tier from `WRITE_OPERATIONS` below: a row stored under
# it is refused (`tier_mismatch`), and a tier-2 row needs the proof decision
# record 0023 describes (`services/confirm/tier_proof.py`).
```

In `services/confirm/callback.py` (line 21), replace

```
        "verification_result": "<tier-2 selfie match reference, if applicable>"
```

with

```
        "verification_result": "<optional; stored for tier 1, ignored for tier 2>"
```

In `services/confirm/callback.py` (lines 150 to 151), replace

```
    This is called by the confirmation service (the operator's banking app)
    after the user completes identity verification and approves the operation.
```

with

```
    This is called by the confirmation service (the operator's banking app)
    after the user approves the operation. For a tier-2 challenge the app
    backend's assertion must also prove that app identity verification
    completed for this challenge (step 2c, decision record 0023).
```

In `services/confirm/callback.py` (lines 162 to 166), replace

```
           cannot sign must not be able to move anybody's challenge.
        3. Claim it: one conditional ``UPDATE`` that carries "still pending"
           and "not yet expired" in its ``WHERE`` and records the verified
           signature + verification_result. Winning it is what authorizes
```

with

```
           cannot sign must not be able to move anybody's challenge.
        2c. Check the row's tier: below its operation's declared tier is
           refused, tier 0 is refused, and tier 2 needs the assertion's
           ``idv``, ``challenge_id``, ``jti`` and ``auth_time``
           (``services/confirm/tier_proof.py``). Before step 3 for the
           reason step 2b gives.
        3. Claim it: one conditional ``UPDATE`` that carries "still pending"
           and "not yet expired" in its ``WHERE`` and records the verified
           signature + verification_result (the body's for tier 1, the
           assertion's ``jti`` for tier 2). Winning it is what authorizes
```

In `services/confirm/callback.py` (lines 297 to 298), replace

```
        # no signature that reached the handler. `detail` below is what says
        # a body arrived and could not be read, as against none arriving.
```

with

```
        # no signature that reached the handler. `detail` below is what says
        # a body arrived and could not be read, as against none arriving.
        # A readable body's `verification_result` is recorded as sent even on
        # a tier-2 row, where `_approve` ignores it and stores the assertion's
        # `jti` instead; `ApprovalAudit.note_assertion_jti` adds that `jti`.
```

In `packages/postern-core/src/postern_core/store/challenges.py` (line 260), replace

```
        verification_result: Tier-2 verification reference (selfie match).
```

with

```
        verification_result: For a tier-1 approval, the approval body's value;
            for tier 2, the ``jti`` of the banking-app assertion that proved
            app identity verification (decision record 0023).
```

In `packages/postern-core/src/postern_core/store/models.py` (lines 962 to 963), replace

```
    ``verification_result``
        Opaque reference to tier-2 verification result (selfie match).
```

with

```
    ``verification_result``
        On a tier-2 row, the ``jti`` of the banking-app assertion that proved
        app identity verification for this challenge (decision record 0023);
        on a tier-1 row, whatever the approval body carried.
```

The two lines after it, about never storing the captured image, stay.

In `packages/postern-core/src/postern_core/domain/verification.py` (line 124), replace

```
        verification_result: Opaque reference to the tier-2 verification result.
```

with

```
        verification_result: Opaque reference to the tier-2 verification result.
            The approval callback does not use this dataclass; on a stored
            tier-2 row the value is the ``jti`` of the banking-app assertion
            that proved app identity verification (decision record 0023).
```

- [ ] **Step 7: The confirm service page**

In `docs/user-guide/components/confirm-service.md`, replace

```
- c. Rejects with 404 unless `challenge.customer_ref` equals that `sub`
```

with

```
- c. Rejects with 404 unless `challenge.customer_ref` equals that `sub`
- c2. After the device signature verifies (below), checks the row's tier and
  refuses with 403, the row left `pending` (see "Tier enforcement" below)
```

and replace

```
configured, the same way it refuses without the app-assertion verifier.
```

with

```
configured, the same way it refuses without the app-assertion verifier.

**Tier enforcement** (since 2026-10-06, decision record 0023). After the signature
verifies and before the row is claimed, the callback reads the row's tier, and
the tier its operation declares in `services/confirm/execute.py`:

| Case | `error` | `detail` in `audit_log` |
|---|---|---|
| Row tier below the operation's declared tier | `tier_mismatch` | `tier_mismatch` |
| Tier 0 (an operation confirm does not declare) | `tier_unsupported` | `tier_unsupported` |
| Tier 2, `POSTERN_CONFIRM_IDV_VALUE` unset | `verification_required` | `verification_not_configured` |
| Tier 2, a claim missing or wrong | `verification_required` | `verification_required` |

A tier-2 approval needs four claims in the banking-app assertion: `idv` equal to
`POSTERN_CONFIRM_IDV_VALUE`, `challenge_id` equal to the challenge in the path, a
`jti` of 1 to 128 printable ASCII characters, and a numeric `auth_time` no earlier
than 30 seconds before the challenge was created and no later than 30 seconds from
now. The row then stores that `jti` as `verification_result`, and both audit rows
record it as `assertion_jti`. Every refusal is a 403 with a fixed description that
names no claim; one WARNING log line names the claim that failed, never its value.
Tier-1 rows are approved as before. What this cannot establish: that the
verification happened. The app backend that mints the assertion is the trust
anchor; [the pairing contract](../../integration/mobile-app-pairing-contract.md)
section 12 lists what it must do.
```

- [ ] **Step 8: The mobile contract (section 10 and a new section 12)**

In `docs/integration/mobile-app-pairing-contract.md`, replace

```
It will get its own contract.
```

with

```
Its request body and the delivery of the challenge to the phone will get their own contract; section 12 states what the assertion must carry to approve a tier-2 challenge.
```

and replace (the last line of the file)

```
- The confirm service's base URL. The app must be configured with it; nothing in the link or the server tells the app where to send `/scan`.
```

with

```
- The confirm service's base URL. The app must be configured with it; nothing in the link or the server tells the app where to send `/scan`.

## 12. Tier-2 challenge approval: what the assertion carries

Decision record `dev-docs/decisions/0023-tier-2-proof-in-the-app-assertion.md`. A payment challenge is tier 2, and `POST /challenges/{challenge_id}/approve` approves a tier-2 challenge only when the assertion authenticating that request carries, beyond section 3's claims:

| Claim | Requirement |
|---|---|
| `idv` | A string equal, exactly, to the value the operator configures in `POSTERN_CONFIRM_IDV_VALUE`. No case folding or trimming. |
| `challenge_id` | A string equal to the challenge in the request path. |
| `jti` | A string of 1 to 128 printable ASCII characters (0x21 to 0x7E). Stored as the challenge's `verification_result` and recorded in `audit_log`. |
| `auth_time` | A JSON number, seconds since the epoch, no earlier than 30 seconds before the challenge was created and no later than 30 seconds after the server's clock. |

Anything else is refused with 403 `verification_required` and a fixed description that names no claim; the challenge stays `pending`, so the app can retry with a corrected assertion until the challenge expires (300 seconds after it was created). With `POSTERN_CONFIRM_IDV_VALUE` unset every tier-2 approval gets the same 403. A tier-1 challenge needs none of the four.

**What the operator's app backend must do.** Confirm checks that the claims are present and consistent. It cannot check that they are true, so the backend owns all of this:

- Set `idv` only from its own record of an identity verification that completed for this `challenge_id` and this `sub`; never from a value the app supplies, and never from the login session.
- Mint at most one tier-2 assertion per verification.
- Use a `jti` unique per issuer, 1 to 128 printable ASCII characters.
- Use an `idv` value that appears in no other claim and that it emits for nothing else.
- Set `auth_time` to the time the verification for this challenge completed. Confirm refuses a value earlier than 30 seconds before the challenge was created or later than 30 seconds from now, and cannot check that the value is true.

Nothing in this repository verifies the selfie match or the order of events; the operator's backend owns both. How the app asks its backend for a tier-2 assertion, and what that backend accepts as input, is not established here and is not part of this contract.
```

- [ ] **Step 9: Gates**

Run: `uv run ruff format packages services tests`
Run: `make lint fmt-check type imports citations`
Expected: every gate passes; `make citations` resolves every anchored citation in the edited files.

- [ ] **Step 10: Full suite, then commit**

Run: `make ci > /private/tmp/claude-501/-Users-stefano-Projects-postern/dce26918-b575-4415-8de8-976663bf0f78/scratchpad/ci-task5.log 2>&1; echo EXIT=$?`
Expected: `EXIT=0`, `4727 passed`.

```bash
git add CLAUDE.md docs/user-guide/getting-started.md docs/superpowers/specs/2026-10-04-payments-producer-core-design.md services/confirm/execute.py services/confirm/callback.py packages/postern-core/src/postern_core/store/challenges.py packages/postern-core/src/postern_core/store/models.py packages/postern-core/src/postern_core/domain/verification.py docs/user-guide/components/confirm-service.md docs/integration/mobile-app-pairing-contract.md
git commit -m "docs: tier-2 approval enforcement, operator item 13 and the app backend contract" -m "Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>"
```

- [ ] **Step 11: Measure the tally on a clean tree**

Run: `git status --short`
Expected: no output (a clean tree).
Run: `git rev-parse --short HEAD`
Note the printed sha; it is the commit Step 10 made.
Run: `make ci > /private/tmp/claude-501/-Users-stefano-Projects-postern/dce26918-b575-4415-8de8-976663bf0f78/scratchpad/ci-tally.log 2>&1; echo EXIT=$?`
Expected: `EXIT=0`. Read the pytest summary line from the log (it has the form `<N> passed, <W> warnings in <S>s`); N is expected to be 4727.

- [ ] **Step 12: Write the measured figures into CLAUDE.md**

In `CLAUDE.md` line 7, replace

```
`make ci` exits 0 on 4616 tests, none failed and none skipped, the test step reporting 340 seconds with Docker up (one run, measured 4 October 2026 on bdfdd6f, a clean tree; the later commits change only documentation (this sentence and an execution record in a plan): `4616 passed, 1547 warnings in 340.41s`).
```

with the same sentence carrying the figures just measured, and nothing else changed: N in place of both `4616`, the rounded seconds in place of `340`, `6 October 2026` in place of `4 October 2026`, the Step 11 sha in place of `bdfdd6f`, `the later commit changes only this sentence` in place of `the later commits change only documentation (this sentence and an execution record in a plan)`, and the summary line verbatim in place of `` `4616 passed, 1547 warnings in 340.41s` ``. Then replace

```
so `tests/test_zt3_deploy_pipeline.py` is inside that 4616 like every other file.
```

with the same text carrying N. The sentence names the commit BEFORE the one that edits it, which is why it does not go stale the way the previous plan's tally line did twice.

- [ ] **Step 13: Commit the tally**

```bash
git add CLAUDE.md
git commit -m "docs: record the tally measured after tier-2 approval enforcement" -m "Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>"
```

Run: `git status --short`
Expected: no output. Report every commit sha of Tasks 1 to 5 to the lead; nothing is pushed.

---

## Self-review

### Spec coverage

| Spec requirement | Task and step |
|---|---|
| 5: declared tier from `WRITE_OPERATIONS`; `row.tier < declared` refused `tier_mismatch` | Task 3 Step 5 (`check_tier`), tests Task 3 Step 1 (mismatch, operations) and Task 4 Step 1 (payment row at tier 1) |
| 5: tier 1 unchanged, body `verification_result` and `confirming_device` stored | Task 4 Step 4 (`stored_verification_result`), tests Task 3 (tier-1 rows) and Task 4 (`test_a_tier_1_row_is_approved_as_before`, both parametrisations) |
| 5: tier 2 ignores the body, stores the `jti` | Task 4 Steps 4 and 1 (happy path, producer approval) |
| 5: tier 0 refused `tier_unsupported`, row pending | Task 3 Step 5, tests Task 3 and Task 4 (`test_a_tier_0_row_is_refused_as_unsupported`); fact (c) |
| 5 step 1: unset refuses `verification_not_configured` | Task 3 Step 5, tests Task 3 and Task 4 (`test_unset_refuses_tier_2_and_still_approves_tier_1`) |
| 5 step 2: `idv` str and exactly equal | Task 3 Step 5, cases `idv-*` in both test files |
| 5 step 3: `challenge_id` str, equal to the path | Task 3 Step 5, cases `challenge-id-*`, A-for-B test |
| 5 step 4: `jti` str, 1 to 128, 0x21 to 0x7E | Task 2 Step 3 (`is_visible_ascii`), Task 3 Step 5, cases `jti-*`, 128-character passes |
| 5 step 5: `auth_time` number, not bool, finite, bounds with 30 s | Task 3 Step 5 (`_auth_time_within`, `ASSERTION_CLOCK_SKEW_SECONDS`), cases `auth-time-*`, exact bounds (Task 3), bool test, huge int (fact d) |
| 6: position between signature verify and claim, same session, refusal writes nothing to `challenges` | Task 4 Step 4; tests: signature first, ownership first, revoked, every refusal asserts `pending` |
| 7: 403, fixed descriptions, four details, one audit row via `audit.raised` | Task 3 Steps 3 and 5 (`tier_refusal`), tests assert the body, `detail` and single `raised` row |
| 7: description never echoes a value; WARNING names the claim, no value | Task 3 Step 5, tests `test_no_description_names_a_claim_or_the_configured_value`, the log tests, and the SENTINEL/IDV checks in Task 4 |
| 7: four `DETAIL_*` literals in `__all__` | Task 3 Step 3 |
| 8: no schema change; `assertion_jti` in the audit arguments, scrubbed and capped, success or refusal after the `jti` passed | Task 4 Step 3 (`note_assertion_jti`, `_with_assertion_jti`), tests: happy path (both rows), `jti_recorded` per refusal case, tier 1 carries none; fact (g) |
| 9: the contract in the mobile doc, replacing "its own contract" for tier 2 | Task 5 Step 8; fact (i) for the `acr` leftover |
| 10: field, validation in `__post_init__` and `from_env`, `""` refused in code, empty env unset | Task 2 Steps 3 and 4, tests Task 2 |
| 10: startup WARNING when unset | Task 2 Steps 4 and 5, tests `test_unset_warns_once`, `test_the_composition_root_warns_exactly_when_unset` |
| 10: inventory row, prose, counts, `not_numeric` | Task 2 Steps 1 and 6; fact (h) |
| 10: compose dev value with placeholder comment | Task 2 Step 7 |
| 10: getting-started row, confirm-service note, CLAUDE.md operator line | Task 2 Step 8, Task 5 Step 3 |
| 11: every table row | Task 4 Step 1 (happy path; each claim; boundaries; A for B; unset; tier 1 both; tier 0; mismatch; signature first; ownership first; revoked; retry; concurrency), Task 2 Step 1 (settings construction), `idv` empty and null are cases in Task 4 Step 1 |
| 11: changed existing test | Task 4 Step 1 (`tests/test_payments_approval_path.py`); the "only test that fails" claim is corrected by fact (a) and Task 1 |
| 11: `verified_claims` docstring | Task 4 Step 5 |
| 11: the twelve mutations | skip the tier check (Task 4, 1); `idv` case-insensitive (Task 3, 1); skip `challenge_id` (Task 3, 2 and Task 4, 5); store the body string (Task 4, 2); accept a missing `jti` (Task 3, 3); drop lower bound (Task 3, 4); drop upper bound (Task 3, 5); accept a bool (Task 3, 6); `< 128` (Task 2, 1 and Task 3, 8); above ownership (Task 4, 3); above signature (Task 4, 4); drop `tier_mismatch` (Task 3, 7 and Task 4, 5). All twelve were run on a copy of the tree and each failed a test |
| 12: CLAUDE.md lines 13 and 128 and the checklist | Task 5 Steps 1 to 3 |
| 12: getting-started line 100 | Task 5 Step 4 |
| 12: producer spec lines 16, 32, 203, 215; producer plan left as is | Task 5 Step 5 |
| 12: `execute.py` 101 to 103; `callback.py` 21, 150 to 151, 163 to 166, 296 to 298 | Task 5 Step 6 |
| 12: `challenges.py` 260, `models.py` 962 to 963, `verification.py` 124 to 126 | Task 5 Step 6 |
| 12: confirm-service step between c and d, and the four details | Task 5 Step 7 |
| 12: mobile contract section 10 line 304 and a new section | Task 5 Step 8 |
| 12: decision record 0023 | Already Accepted and aligned; no edit |
| 13, 14 | Nothing to build; operator item 13 (Task 5 Step 3) and item 12 keep gates 2 and 3 and the safe default |

### Placeholder scan

No step says TBD, TODO, "similar to" or "add error handling". Every code step carries its complete code, every replacement its exact old and new text, every run step its command and expected result. The one value not known in advance is the measured tally in Task 5 Step 12, and that step says exactly which numbers replace which and where they come from.

### Names used across tasks

`MAX_VISIBLE_ASCII_LENGTH`, `is_visible_ascii`, `_check_idv_value`, `warn_if_idv_value_unset`, `ConfirmSettings.idv_value` (Task 2; `is_visible_ascii` reused in Task 3); `DETAIL_VERIFICATION_REQUIRED`, `DETAIL_VERIFICATION_NOT_CONFIGURED`, `DETAIL_TIER_MISMATCH`, `DETAIL_TIER_UNSUPPORTED` (Task 3, read in Tasks 3 and 4 tests); `check_tier`, `tier_refusal`, `TierVerdict` with `refusal` and `assertion_jti`, `TierRefusal` with `error`, `detail`, `description`, `failed_claim`, `VERIFICATION_REQUIRED_DESCRIPTION`, `TIER_MISMATCH_DESCRIPTION`, `TIER_UNSUPPORTED_DESCRIPTION` (Task 3, used in Task 4); `ApprovalAudit.note_assertion_jti`, `_with_assertion_jti`, `ASSERTION_JTI_ARGUMENT` with the value `assertion_jti` (Task 4); `stored_verification_result` (Task 4). Each is defined in the task that first uses it or an earlier one. The test files define their own helpers (`record`, `claims`, `without`, `check`, `required`, `seed`, `tier2_claims`, `bearer`, `approve`, `stored`, `audit_rows`, `new_challenge_id`, `build_app`) and share none.

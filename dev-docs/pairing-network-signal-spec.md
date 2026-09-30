# Pairing network signal: where the pairing was created, against where it was scanned

**Date:** 30 September 2026
**Status:** specification. The design was approved by capo on 30 September 2026; this document specifies it and decides the points that approval left open. Nothing here is built.
**Against:** `services/confirm/device_auth.py`, `services/confirm/audit.py` and `packages/postern-core/src/postern_core/auth/device_codes.py` at `31103cf`.
**Follows:** `dev-docs/qr-page-spec.md`, whose "What this does not fix" names this signal as the next spec and whose §1 added `creator_ip` to the pairing so that this one would have something to compare.

---

## What this fixes, first

Nothing is compared today. `POST /device_authorization` records the creator's address on the pairing (`creator_ip` on `packages/postern-core/src/postern_core/auth/device_codes.py::DeviceCode`, taken through `services/confirm/audit.py::pairing_client_ip` in `services/confirm/device_auth.py::device_authorization`), and the comment above that call says it is "RECORDED AND READ BY NOTHING YET". `POST /scan` records the scanner's address on its audit row and nowhere else, and forgets which pairing's creator it should be set against.

The two phishing forms in the QR page spec have one thing in common: the pairing is created by the attacker's AI client, on the attacker's network, and scanned by the victim's phone, on the victim's network. The consent lure (an emailed `/verify?d=<handle>` link) and the live relay (a phishing page re-serving `qr.svg`) both pass every check the QR page added, because the code the victim compares is genuine. The only server-side trace they leave is that the two networks differ.

This spec records that comparison on every successful scan, so that:

- an investigator asking "was this pairing completed from somewhere other than where it started" gets an answer from `audit_log` with one JSONB predicate, and
- whoever writes the policy spec has a population to measure before choosing a threshold.

## What this does not fix

**It refuses nothing and changes no response.** A scan whose networks differ is answered exactly as one whose networks match. Whether to step up, refuse or only record is a later decision, and it needs the population this spec starts collecting before it can be made honestly.

**"Different" is the normal case for a legitimate customer, not only for an attacker.** Each of these produces `different` for a customer doing nothing wrong:

- A laptop on home Wi-Fi and a phone on mobile data. This is probably the most common legitimate pairing, and nothing on the server can tell it from the lure.
- A laptop on a corporate VPN or a consumer VPN, and a phone that is not.
- An AI client that calls `POST /device_authorization` from the vendor's servers rather than from the user's machine. For such a client `creator_ip` is the vendor's egress address for every customer, legitimate or not, and the relation is `different` on every pairing. **Which of the clients the handoff names call the device grant from the user's machine and which from their own infrastructure has not been checked.** Until it is, the signal is interpretable only for clients known to run locally.

**"Same" is weaker evidence than it reads.** Mobile carriers put many subscribers behind one public IPv4 address (carrier-grade NAT), so an attacker on the same carrier as the victim can produce `same_ip` or `same_prefix`. So can an attacker on the same café, hotel or corporate network. `asn_match` and `country_match` are cheaper still to satisfy: a residential proxy in the victim's country and on the victim's ISP costs an attacker money, not skill.

**It is meaningless with the default proxy setting.** Under `POSTERN_CONFIRM_TRUSTED_PROXY_HOPS=0`, the default, `packages/postern-core/src/postern_core/net.py::client_ip` returns the socket peer. Behind a load balancer that is the balancer's address, on both sides of the comparison. A balancer with several nodes then produces `same_ip`, `same_prefix` or `different` according to which nodes carried the two requests, which is noise that reads as data. §5 records the hop count on every row so that such rows can be told apart afterwards; nothing makes them useful.

**The browser that shows the page is not compared.** `GET /verify` and `/verify/state` come from the browser the customer is looking at, which for a hosted AI client is the only request in the flow made from the customer's own machine. This spec compares creator and scanner, as approved, and does not record the page's address. Whether the page's address is the better comparison is an open question for the policy spec, stated in "Open questions".

---

## Design

### 1. Store: `scanner_ip` on the pairing

`DeviceCode` gains one field:

| Field | Type | Purpose |
|---|---|---|
| `scanner_ip` | `str \| None`, default `None` | The address of the `POST /scan` request that claimed the pairing, via `services/confirm/audit.py::pairing_client_ip` with the confirm service's `trusted_proxy_hops`. Recorded only; nothing in this spec reads it from the store. |

It is serialized exactly as `creator_ip` is, in `_device_code_to_dict` and `_device_code_from_dict` in `packages/postern-core/src/postern_core/auth/device_codes.py`: key `"scanner_ip"`, value the string or JSON `null`, and on the way back `str(raw)` when the key is present and not null, `None` otherwise. A record written before this change has no key and deserializes with `scanner_ip=None`. That is the true reading, not a fail-closed default: the previous release recorded no scanner address, so there is none.

**`claim_scan` gains a required keyword-only argument**, `scanner_ip: str | None`, on the abstract `packages/postern-core/src/postern_core/auth/device_codes.py::DeviceCodeStoreBase` and on both backends. Required and nullable rather than defaulted, for the reason the `client_id` parameter of `packages/postern-core/src/postern_core/store/audit.py::append` gives: a default lets a future caller record "no address" for a scan that had one.

**Written on `CLAIMED` only. First scan wins.** Both backends already write the row on `CLAIMED` alone (`packages/postern-core/src/postern_core/auth/device_codes.py::claim_scan` on the in-memory store replaces the dataclass, the Redis store `SET`s it with `KEEPTTL`); `scanner_ip` joins `scanned_by` and `scanned_at` in that same `dataclasses.replace`, so it is set in the same compare-and-set and cannot be written without them. `ALREADY_MINE` writes nothing, as it does today. The reasons:

- `ALREADY_MINE` serves only a retried request (the QR page spec's §1). The pairing was claimed by the first request, so that request's address is the scanner's address.
- Overwriting on a retry would let the address on the pairing drift to whichever network the phone was on at its last retry, which is a later and less meaningful fact than where the claim was made.
- Writing on `ALREADY_MINE` would turn a read-only result into a write, and the store contract says every result except `CLAIMED` and `CONFLICT_REVOKED` writes nothing.

`_scan_verdict` in the same file is unchanged: the address plays no part in which `ScanClaim` a row earns.

**Retention of both addresses on the pairing.** `creator_ip` and `scanner_ip` live on the device-code row and nowhere else, and that row lives until its TTL (`device_code_ttl_seconds`, 900 seconds by default), or until it is revoked (a `conflict_revoked` scan, or `_withdraw_pairing` in `services/confirm/device_auth.py`). A successful exchange at `/token` does not remove it. So an investigator has the creator's address for at most the pairing's lifetime. After that, the audit row's relation is the durable record, and the creator's address is gone. See §4 for why this spec keeps it that way.

### 2. The classifier: `postern_core.risk.pairing_network`

A new module, `packages/postern-core/src/postern_core/risk/pairing_network.py`. **Pure:** it imports `ipaddress`, `enum`, `dataclasses`, `typing` and `postern_core.risk.types`, reads no environment, performs no I/O and holds no state. It carries:

**`NetworkRelation`**, a `str` enum with exactly four values:

| Value | When |
|---|---|
| `same_ip` | Both addresses parse and are equal as `ipaddress` objects. |
| `same_prefix` | Both parse, are the same family, are not equal, and share a /24 (IPv4) or a /48 (IPv6). |
| `different` | Both parse and neither of the above holds. **Mixed families are always `different`.** |
| `unknown` | Either address is `None`, or either fails `ipaddress.ip_address`. |

**`classify(creator_ip: str | None, scanner_ip: str | None) -> NetworkRelation`**, total over its inputs: it never raises. An unparsable string is `unknown`, not an exception, because `creator_ip` is read back out of a store and a corrupted value must not fail a scan.

The prefixes are the approved /24 and /48, computed with `ipaddress.ip_network(f"{addr}/{bits}", strict=False)`. They are deliberately not `packages/postern-core/src/postern_core/net.py::ip_bucket`'s /64: that function answers "which rate-limit counter does this address spend", this one answers "could these two requests plausibly be the same site". A /48 is the allocation commonly given to one end site; a /64 is one link inside it, and a laptop on Ethernet and a phone on Wi-Fi in the same house can be on two.

**IPv4-mapped IPv6 addresses are compared as IPv6.** `client_ip` canonicalises `::FFFF:1.2.3.4` to `::ffff:1.2.3.4` (measured on the project's CPython 3.12.13: the result has `version == 6`), and does not unwrap it. Under the approved rule, that address against `1.2.3.4` is mixed families and therefore `different`. This is the conservative reading and it is recorded under "Discrepancies".

**`NetworkFacts`**, a frozen dataclass with `asn: int | None` and `country: str | None`: what an enricher knows about one address.

**`MatchResult`**, a tri-state: `True`, `False` or the string `"unknown"`. §5 gives the JSON.

**`compare_facts(creator: NetworkFacts | None, scanner: NetworkFacts | None) -> tuple[MatchResult, MatchResult]`** returns `(asn_match, country_match)`. For each field: `True` when both sides carry a value and the values are equal, `False` when both carry a value and they differ, `"unknown"` otherwise (either side `None`, or either field `None`). Country codes are compared after `str.upper()`.

**`pairing_network_signal(relation, proxy_hops, asn_match=None, country_match=None) -> RiskSignal`**, which builds the one `packages/postern-core/src/postern_core/risk/types.py::RiskSignal` §5 serializes. Match arguments of `None` mean "no enricher installed" and omit the keys; §5 says why absent differs from `"unknown"`.

### 3. The enricher seam

**The Protocol**, in the same pure module:

```python
class NetworkEnricher(Protocol):
    async def lookup(self, ip: str) -> NetworkFacts | None: ...
```

One method. `None` means "no data for this address", which is the normal answer for a private or reserved range.

**Async, not sync, decided here.** `/scan` runs on the event loop that serves every other request on the replica. A synchronous lookup that blocks (a cold disk read, a DNS resolution, an HTTP call someone wrote with a blocking client) would stall every request in that process for its duration, and moving it to `asyncio.to_thread` bounds the wait but not the work: a thread cannot be cancelled, so a hung provider accumulates threads until the default executor is exhausted. An async method can be cancelled at the budget. A provider backed by a local database file implements `async def lookup` and returns without awaiting anything; the cost of async to that provider is one keyword.

**Discovery**, by entry point, following decision 0018 and the loaders it describes (`packages/postern-core/src/postern_core/modules/read.py::load_read_modules` and `packages/postern-core/src/postern_core/modules/write.py::load_write_modules`):

- Group `postern.pairing_network_enrichers`. The value resolves to an **instance** satisfying the Protocol, as a module's entry point resolves to its `MODULE` instance rather than to a class.
- The loader is a new module, `packages/postern-core/src/postern_core/modules/enrichers.py`, holding the group-name constant, an exception `EnricherSeamViolation(RuntimeError)` and `load_network_enricher() -> NetworkEnricher | None`. It lives beside the two existing loaders and not in `postern_core.risk.pairing_network`, so that module stays free of `importlib.metadata`. The group name is not added to `packages/postern-core/src/postern_core/modules/groups.py`: that module exists to keep the write group's name reachable from the read path without the write half's types, and no such constraint applies here.
- **Zero installed: `None`, and no enrichment.** Rows then carry the relation and no match keys.
- **More than one installed: refuse to start**, raising `EnricherSeamViolation` naming every entry point found. Two providers disagreeing about one address has no correct resolution, and choosing by installation order is the failure decision 0018 refuses for write routing.
- **An entry point that will not import, or resolves to an object whose `lookup` is not a coroutine function** (`inspect.iscoroutinefunction`): refuse to start, the way `_load` in each existing loader refuses a wrong type. A `typing.runtime_checkable` check alone is not enough, because it tests that the attribute exists and not that it is async, and a sync `lookup` would then block the loop.
- **Called once, in `services/confirm/main.py::create_confirm_app`**, before the app is built, and stored on `app.state.pairing_network_enricher`. A refusal therefore lands at composition, where every other installed-distribution refusal in this repository lands. `create_confirm_app` gains a keyword argument for tests to supply an enricher or an explicit absence, the way it already takes `device_key_store`; because `None` is a meaningful value there ("no enricher"), the default is a private sentinel meaning "load from entry points".

**The time budget.** Both lookups (creator and scanner) run concurrently inside one `asyncio.timeout(budget)`. The budget is a new setting:

| Setting | Env var | Default | Bounds |
|---|---|---|---|
| `pairing_enricher_timeout_seconds` | `POSTERN_CONFIRM_PAIRING_ENRICHER_TIMEOUT_SECONDS` | `0.25` | above 0 and at most 1.0 |

Declared like every other confirm setting: a `services/confirm/settings.py::ConfirmSettings` field, read in `ConfirmSettings.from_env` through `packages/postern-core/src/postern_core/config.py::float_from_env` with `minimum=0, exclusive=True`, and an `EnvVar("POSTERN_CONFIRM_PAIRING_ENRICHER_TIMEOUT_SECONDS", "number", ("confirm",))` entry in `packages/postern-core/src/postern_core/env_inventory.py`. `float_from_env` has no upper bound, so `from_env` refuses a value above 1.0 itself with a `ValueError`, as it refuses an out-of-range device-code TTL. The ceiling exists because the budget is added to a successful scan's latency while the customer holds their phone, and because it widens the window between a committed claim and its audit row (§4). The default of 250 ms is a choice, not a measurement: no provider exists to measure.

**Failure is never a refused scan.** Every outcome other than two completed lookups is `"unknown"` for both matches:

- the budget expires (both lookups are cancelled; one that finished alone is discarded, because a comparison needs both sides);
- either lookup raises any `Exception`;
- either lookup returns something that is not `NetworkFacts` or `None`.

A field that fails validation becomes `None` for that field only: `asn` must be an `int` that is not a `bool` and lies in 0 to 4294967295, and `country` must be two ASCII letters. Anything else from the provider is discarded, never stored and never logged.

Each failure writes one `WARNING` log line naming the exception's type or "timeout", and never either address. The volume is bounded by the scan limits already in front of the route (`rate_limit_scan`, 60 a minute per address, and `customer_rate_limit_scan`, 10 a minute per customer): at most two lookups per successful scan.

`asyncio.CancelledError` from the request itself is not caught, as `services/confirm/device_auth.py::_scan` already does not catch it around `claim_scan`. A provider that suppresses cancellation defeats the budget; the host cannot bound it further without a thread, and that is a provider bug this spec names rather than engineers around.

**Lookups are skipped where they cannot change the answer.** When the relation is `unknown`, one address is missing, so both matches are `"unknown"` without a lookup. When it is `same_ip`, both matches are `True` without a lookup: one address has one ASN and one country, and asking twice would only measure the provider's consistency. Only `same_prefix` and `different` spend the budget.

**Trust.** An enricher runs inside `services/confirm`, which holds the write signing key, and it is handed every creator and scanner address. Decision 0018's "What a malicious module can do" applies without softening: installing one is as consequential as merging a commit into this repository. Two consequences an operator owns:

- A provider that calls an HTTP API needs an egress exception from the confirm service, which ZT-8's default-deny egress exists to refuse, and it sends customers' addresses to a third party. A provider reading a local database file needs neither.
- `packages/postern-core/src/postern_core/env_inventory.py::enforce_known_environment` refuses to start a confirm process whose environment holds a `POSTERN_`-prefixed name the inventory does not list. A provider distribution cannot add inventory entries, so it must read its own configuration under its own prefix.

Because `site-packages` is copied whole into both images (decision 0018), an installed enricher distribution is also present in the api image. Nothing there loads it.

### 4. Where it runs in `/scan`

In `services/confirm/device_auth.py::scan_callback`, the scanner's address is computed **once**, into a local, and passed both to the `PairingAudit` constructor (as `client_ip_value`, as today) and to `_scan`. Computing it twice would let the row and the pairing disagree if the two reads ever diverged.

In `services/confirm/device_auth.py::_scan`:

1. `claim_scan` is called with `scanner_ip=` that address.
2. On `CLAIMED` or `ALREADY_MINE`, and on no other result, the signal is built: `classify(code.creator_ip, scanner_ip)`, then enrichment under §3's rules, then `pairing_network_signal`. `code` is the row `_lookup_by_user_code` returned before the claim; `creator_ip` is written once, at creation, and never changed, so the pre-claim row is the right one to read it from.
3. The serialized signal is returned on `_Scanned`, in a new field, and `scan_callback` hands it to the audit writer for the success row.

On `ALREADY_MINE` the relation compares the creator with **this** request's address, not with the stored `scanner_ip`. The row then describes the request it records: the address beside it in `arguments` is the one the relation was computed from.

**The signal step must not raise.** `scan_callback`'s exception branch records a refusal and withdraws nothing, and its comment states why that is safe: "nothing after a successful claim can raise". A raise from enrichment would break that premise and leave a claimed pairing recorded as refused. §3's rule that every lookup failure becomes `"unknown"` is what keeps the premise true; `classify` and `compare_facts` are total. A test pins it (Testing).

**The window this adds.** Between the committed claim and the audit row, the claimed pairing exists un-audited for up to the enrichment budget longer than today. The fail-closed withdrawal in `scan_callback` is unchanged and still covers an audit write that fails after it.

**Refusals carry no signal.** Every `/scan` refusal row keeps `risk_signals` NULL, including `scan_conflict`, where a second customer's network would be interesting. That is deliberate: the approved design records the relation on successful scans, and a conflict row compares a customer with a pairing that was never theirs.

### 5. The audit row

**Which column.** `risk_signals`, the existing JSONB column on `packages/postern-core/src/postern_core/store/models.py::AuditEntry`, typed `list[dict[str, Any]] | None`. No migration: the column exists, is nullable and carries no constraint on its contents.

**Exact shape.** A one-element array, in the four-key object shape `services/api/middleware/audit.py::AuditMiddleware` writes for the read path (`code`, `severity`, `description`, `details`, with `severity` as the `Severity` member's name):

```json
[
  {
    "code": "PAIRING_NETWORK",
    "severity": "LOW",
    "description": "pairing creator and scanner network relation: different",
    "details": {
      "relation": "different",
      "proxy_hops": 2,
      "asn_match": false,
      "country_match": true
    }
  }
]
```

| Key | Value |
|---|---|
| `code` | always `"PAIRING_NETWORK"`, upper case like the read path's `IMPOSSIBLE_TRAVEL` |
| `severity` | always `"LOW"`. The column's shape requires one, and `LOW` is the severity whose action in `packages/postern-core/src/postern_core/risk/types.py::RiskAction` is to log. Grading `different` as higher would announce a policy this spec does not have. |
| `description` | `"pairing creator and scanner network relation: "` followed by the relation value. Fixed text, no address. |
| `details.relation` | one of `same_ip`, `same_prefix`, `different`, `unknown` |
| `details.proxy_hops` | the confirm service's `trusted_proxy_hops` when the row was written. `0` marks a row whose relation compares a load balancer with itself unless the service is exposed directly; it is how a reader filters out the rows "What this does not fix" calls noise. |
| `details.asn_match`, `details.country_match` | `true`, `false` or `"unknown"`. **Both keys absent when no enricher is installed.** |

**Absent versus `"unknown"`** follows the convention `PairingAudit` already uses for `arguments`: a key that is absent says the step never ran, a value says it ran and this is what it found. `"unknown"` means an enricher was installed and could not answer; absence means none was installed. The mixed JSON types are chosen so that `details->>'asn_match'` yields the text `true`, `false` or `unknown` uniformly, and `details ? 'asn_match'` tells the two absences apart.

**No addresses in the JSON, and no ASN numbers or country codes either.** The details carry only comparisons and a closed vocabulary chosen by this code, so no value in them comes from a caller or a provider. That is also why they need no pass through the scrubbing and bounding `PairingAudit` applies to `arguments`, and why they spend nothing from the request's redaction budget. (The read path's own `IMPOSSIBLE_TRAVEL` signal does put raw addresses into its `details`; this signal does not follow it there.)

**Where each address is, for an investigator.**

- **Scanner:** on the same row, as `arguments.client_ip`, written by `services/confirm/audit.py::PairingAudit` whenever it is not `None`. Retained as long as `audit_log` is, which is append-only.
- **Creator:** on the device-code row only, for the pairing's lifetime (§1), after which it exists nowhere. This spec does not copy it into `audit_log`. Copying it would put a second customer-linked address into an append-only table on every pairing, for a comparison already recorded. It would also need a row at `POST /device_authorization`, which `PairingAudit`'s rule refuses because that endpoint resolves no identity. If investigations turn out to need the creator's address after 15 minutes, that is a retention decision for the operator's DPO, and a later spec's.

**Writer change.** `PairingAudit` gains a way to carry the serialized signal to `_write` for the success row (a keyword argument on `approved`, used only by `/scan`), and `_write` passes it as `risk_signals`. Every other row the class writes, on `/approve`, `/token` and every `/scan` refusal, keeps `risk_signals=None`. The comment above that argument in `services/confirm/audit.py::PairingAudit` currently says NULL is "the true statement" because no risk session exists in this service; it is rewritten to say that NULL is still true for every row except a successful scan, which carries exactly one signal and no session.

**It never refuses and never changes a response.** The success body of `/scan` is byte-identical with and without the signal, with and without an enricher, for every relation.

### 6. Documentation

`POSTERN_CONFIRM_TRUSTED_PROXY_HOPS`'s row in `docs/user-guide/getting-started.md` gains one sentence: the pairing network signal compares addresses taken through this setting, so under the default both are the load balancer's and the recorded relation means nothing. The new timeout setting gets a row beside it. `docs/user-guide/components/confirm-service.md` gains a short paragraph describing the signal, its JSON shape, the enricher entry-point group and the trust statement from §3.

Two code comments become false when this lands and are rewritten with it: the `DeviceCode` docstring's "nothing reads it yet" on `creator_ip`, and the "RECORDED AND READ BY NOTHING YET" comment in `device_authorization`.

---

## Discrepancies

Each was found by reading the code against the approved design. Where the two disagree, this spec takes the conservative reading and says so.

1. **There is no client-address column on `audit_log`.** The design says "the row already carries the client address column". It carries the address as the key `client_ip` inside the `arguments` JSONB, and only when the address is not `None` (`services/confirm/audit.py::_arguments`). The conclusion survives, since the scanner's address is on the row, but a query must read `arguments->>'client_ip'`. This spec adds no column.
2. **The `risk_signals` column comment and its only writer disagree about the object shape.** The comment on `AuditEntry` names three keys (`code`, `severity`, `details`); `AuditMiddleware` writes four, adding `description`. This spec follows the writer, so that one query shape reads both services' rows.
3. **`IpAnomalyDetector` has no ASN data to reuse.** Its module docstring lists "ASN change" as a detected class, but `evaluate` has no such check, `packages/postern-core/src/postern_core/risk/ip_anomaly.py::_suspicious_asn_detected` returns `False` unconditionally with the comment "No ASN enrichment yet", and `IpTracker` carries no ASN field. The enricher seam here would be the first ASN source in the repository. Wiring it into the read path's detector is out of scope.
4. **IPv4-mapped IPv6 addresses.** The design says mixed families are `different` and does not mention mapped addresses. `client_ip` returns `::ffff:a.b.c.d` as an IPv6 address, so such an address against its own IPv4 form is `different` under the literal rule. Taken literally here, because the conservative direction for a signal that may later relax a check is to under-claim sameness. Unwrapping with `ipv4_mapped` before classifying is a one-line change if capo prefers it.
5. **`claim_scan`'s signature changes.** The design adds a field but does not say how the address reaches the store. It must reach it through `claim_scan`, since that is the only transaction that writes `scanned_by`, and every existing caller and test double of `claim_scan` changes with it.

## Decisions made here

The brief left these open, and each is decided above:

- `scanner_ip` is written on `CLAIMED` only (§1).
- Lookup is async, with one shared budget of 250 ms, configurable up to 1.0 s (§3).
- No addresses, ASN numbers or country codes in the JSON; the creator's address is kept only on the pairing for its lifetime (§5).
- `severity` is always `LOW`; `details.proxy_hops` is recorded on every row (§5).
- Lookups are skipped for `unknown` and `same_ip` (§3).
- The loader lives in `postern_core.modules`, the classifier in `postern_core.risk` (§3).

---

## Testing

Test-first throughout. What must exist when this lands:

- **Classifier**, table-driven: equal IPv4 and equal IPv6 (`same_ip`); two IPv4 addresses in one /24 and in adjacent /24s; two IPv6 addresses in one /48 and in adjacent /48s, including two in different /64s of one /48 (`same_prefix`, the case `ip_bucket` would split); IPv4 against IPv6 and a mapped address against its IPv4 form (`different`); `None` on either side, both `None`, and an unparsable string on either side (`unknown`); that `classify` raises for no input in the table.
- **`compare_facts`**: every combination of present, `None` and field-`None` on both sides, for both fields; country compared case-insensitively.
- **Signal JSON**: the exact object for each relation with an enricher and without; the match keys absent without one; no address, ASN number or country code in the serialized output for any input (asserted by searching the JSON text for the inputs).
- **Store, on both backends** (Redis against the container `make ci` already runs): `CLAIMED` sets `scanner_ip` together with `scanned_by` and `scanned_at`; `ALREADY_MINE`, `APPROVED_MINE`, both conflicts and `GONE` leave it unchanged; a `None` address is stored as `None`; round-trip serialization; a record without the key deserializes with `None`; `claim_scan` without `scanner_ip` is a `TypeError`.
- **Loader**, with fake distributions the way `tests/test_module_seam.py` builds them: none installed gives `None`; one gives it; two refuse with both names; one that fails to import refuses; one whose `lookup` is synchronous refuses; `create_confirm_app` refuses at composition for each refusal.
- **Enrichment in `/scan`**: a provider that raises, one that sleeps past the budget, one that returns a wrong type, and one that returns an out-of-range ASN or a three-letter country, each producing `"unknown"` with a 200 response and one log line containing neither address; a provider that suppresses nothing and answers within budget producing `true` and `false`; no lookup made for `same_ip` or `unknown` (a provider that fails the test if called).
- **`/scan` rows**, over ASGI with `POSTERN_CONFIRM_TRUSTED_PROXY_HOPS` set and `X-Forwarded-For` supplied, because the in-process client has no peer and under zero hops both addresses are `None`: a `CLAIMED` success row and an `ALREADY_MINE` row each carrying the one-element array with the right relation and `proxy_hops`; the `ALREADY_MINE` row's relation computed from its own request's address; every refusal row, `scan_conflict` included, with `risk_signals` NULL; `/approve` and `/token` rows still NULL; the 200 body identical across all four relations and with or without an enricher.
- **The premise in §4**: an enricher whose `lookup` raises during a `CLAIMED` scan leaves the pairing claimed and the row `returned`, never refused.
- **Settings**: the timeout's default, its env_inventory entry, and refusals at 0, a negative value, `nan`, `inf` and 1.01.

Existing tests that change: every call of `claim_scan`, which at `31103cf` appears in `tests/test_device_code_pairing_store.py`, `tests/test_redis_backed_stores.py`, `tests/test_device_grant.py`, `tests/test_scan.py`, `tests/test_verify_page.py` and `tests/device_grant_helpers.py`, plus any test double implementing `DeviceCodeStoreBase`; and `tests/test_settings_bounds.py` for the new setting. No existing test asserts `risk_signals` on a pairing row, so none pins the NULL this spec replaces.

## Size

Four production files changed and two added. Roughly 200 lines of production code: the classifier, facts and signal builder about 90, the loader about 60, store changes about 15, handler and audit writer about 35, settings about 20. Roughly 500 to 700 lines of tests.

## Owed outside this repository

- **`POSTERN_CONFIRM_TRUSTED_PROXY_HOPS` set correctly in every deployment.** Without it every row this spec writes is noise.
- **Which clients create pairings from the user's machine.** For each MCP client the operator expects, whether `POST /device_authorization` comes from the user's device or the vendor's infrastructure. Until that is known, a `different` relation cannot be read for that client.
- **An enricher, if one is wanted**, and its data source's licence and update cadence. None ships here.
- **A DPO view** on deriving ASN and country from customers' addresses, and on sending those addresses to a provider if the chosen one is remote.
- **The policy.** Whether any relation should step up or refuse a pairing, decided against the population this spec records.

## Open questions, for the policy spec

- Whether the page's address (`GET /verify`) is a better comparison than the creator's for hosted AI clients, where the creator is the vendor.
- Whether mapped IPv4 addresses should be unwrapped before classifying (Discrepancy 4).
- Whether a row should flag a private or loopback address on either side, which is the usual trace of a misconfigured hop count.

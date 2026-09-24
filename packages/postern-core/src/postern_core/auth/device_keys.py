"""Where a customer's enrolled DEVICE public keys come from.

WHAT THIS CLOSES. ``services/confirm/callback.py`` required the approval body
to carry a non-empty ``signature``, stored it on the challenge row, and
verified nothing. Its own module docstring named the residual in one sentence:
the app assertion proves the operator's app is calling for this customer, and
nothing proved the human held the device and consented. Anything able to mint
or steal an app assertion could approve that customer's pending challenges
without the phone ever being touched. Verifying the signature needs one thing
this repository did not have -- an answer to "which public key belongs to this
customer's enrolled device" -- and this module is that seam.

THE SEAM IS A HYBRID OF THE TWO THIS REPOSITORY ALREADY HAS, deliberately,
because the two answer different halves of the question:

- CONFIGURATION follows `postern_core.auth.keys`'s `KeySource`. Key material
  reaches the process as a file the operator renders (there, a PEM a Vault
  Agent sidecar writes; here, a JWKS-shaped JSON document an enrolment system
  publishes), named by a field on the service's settings, and NO TEST IN THIS
  REPOSITORY ENROLS A REAL DEVICE. Populating it is the operator's job in the
  same sense that populating Vault is.
- THE INTERFACE follows `postern_core.auth.revocation`'s
  `RevocationStoreBase`: an async ABC with in-process and file backends here,
  and room for the one an operator actually runs -- their enrolment database
  behind an HTTP call -- without a caller learning which it holds. Async even
  though both backends below answer from memory, for that reason and for the
  same reason that base is: a store that cannot answer must be able to raise,
  and a real one does I/O.

It is deliberately NOT `create_device_code_store`'s shape, despite the
adjacent name. `postern_core.auth.device_codes` holds RFC 8628 DEVICE CODES --
short-lived, server-generated, one per pairing attempt, and correctly keyed on
``POSTERN_REDIS_URL`` because every replica must see one another's. These are
long-lived PUBLIC keys belonging to the customer's phone, written by an
enrolment flow this repository does not contain and does not want to invent.
Putting them behind the same environment variable would say they are cache,
and they are not: an empty Redis means "nothing revoked" for that store and
would mean "nobody can approve a payment" for this one.

WHAT AN OPERATOR OWES. Enrolment. When a customer registers a phone, the app
generates an Ed25519 key pair in the device's secure element, keeps the private
half there, and publishes the public half into whatever store backs this
interface. Rotation and de-enrolment are the same operation: the set this
returns for a customer is the set of devices that may approve their payments
right now. Nothing in this repository writes to it.

WHY Ed25519 AND NOT RSA, given every other key in this tree is RSA-2048. The
signer is a phone, the verifier is on the hot path of a payment, and the key
travels through an enrolment system: 32-byte public keys and 64-byte
signatures against 256-byte RSA ones, hardware support in both Secure Enclave
and Android Keystore, no padding mode to get wrong, no parameter that can be
weakened without changing the curve name. The service's own signing keys are
RSA because they mint JWTs that third parties verify against a published JWKS
and RS256 is what every verifier accepts; nothing about that argument reaches
a raw signature over a locally-defined message.

NO NEW DEPENDENCY. Verification is `joserfc`'s ``EdDSAAlgorithm``, already a
direct dependency of ``postern-core`` (``joserfc>=1.7.5,<2``) and already the
library `postern_core.auth.keys` imports; it is a thin wrapper over
``cryptography``'s ``Ed25519PublicKey.verify``. ``cryptography`` itself is in
``uv.lock`` only as joserfc's own transitive dependency, and importing it
directly would mean declaring it directly and pinning a second version range
for one function call. `postern_core.auth.approval_signature` holds that call.

Usage::

    store = FileDeviceKeyStore(Path("/run/postern/device-keys.json"))
    keys = await store.keys_for("cust_7f3a")   # () when nobody enrolled
"""

from __future__ import annotations

import json
import logging
import warnings
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final, Literal

from joserfc.jwk import OKPKey

logger = logging.getLogger(__name__)

#: The only curve this repository will verify an approval against. ``OKP`` also
#: covers Ed448 (signing) and X25519/X448 (key agreement, which cannot sign at
#: all), and `joserfc`'s ``EdDSAAlgorithm`` accepts Ed448 as readily as
#: Ed25519. Accepting either would mean the answer to "what was verified"
#: depends on the enrolment record rather than on this file, so a store loads
#: one curve and refuses the rest.
REQUIRED_CURVE: Final[Literal["Ed25519"]] = "Ed25519"

#: How many enrolled keys one customer may carry. Every key is tried on every
#: approval (`postern_core.auth.approval_signature`'s
#: ``verify_approval_signature``), so an unbounded set turns one approval into
#: unbounded verification work for whoever wrote the enrolment record. Sixteen
#: is far past any real device count and far short of a cost that matters.
#: `FileDeviceKeyStore` enforces it when the file loads, which is startup; a
#: store an operator writes against their own enrolment database owes the same
#: bound, because this module cannot enforce it from the outside.
MAX_KEYS_PER_CUSTOMER = 16


class DeviceKeyStoreUnavailable(RuntimeError):
    """The store could not answer, so the approval must be refused.

    Never collapsed into "this customer has no enrolled device". The two are
    different events with the same refusal, and
    ``services/confirm/audit.py``'s ``DETAIL_DEVICE_NOT_ENROLLED`` is written
    for exactly one of them -- an outage recorded as the other would tell an
    operator that their customers had stopped enrolling phones. The same
    argument `postern_core.auth.revocation`'s `RevocationStoreUnavailable`
    makes for not reporting an outage as "not revoked".
    """


@dataclass(frozen=True)
class EnrolledDeviceKey:
    """One public key one customer may approve with.

    ``kid`` is the operator's own identifier for the enrolled device. It is
    never matched against anything the caller sends: a request does not get to
    choose which key it is verified under, because that choice is an input and
    the point of this control is that the caller supplies exactly one thing,
    the signature.
    """

    kid: str
    key: OKPKey


class DeviceKeyStoreBase(ABC):
    """The enrolled-device surface, in whichever backend.

    One method, because one question is asked: which keys may approve for this
    customer, right now. Enrolment, rotation and de-enrolment are the
    operator's writes into whatever backs it, and giving this interface
    mutators would invite a route on this service that performs them -- which
    is the argument `postern_core.auth.revocation` makes for having a CLI
    rather than an admin endpoint, only sharper, because enrolling a key IS
    the authority to move that customer's money.
    """

    @abstractmethod
    async def keys_for(self, customer_ref: str) -> tuple[EnrolledDeviceKey, ...]:
        """Every key currently enrolled for this customer, possibly none.

        An empty tuple means this customer has no device enrolled, which is a
        refusal and not an error. Raises `DeviceKeyStoreUnavailable` when the
        store cannot answer at all, which is a different refusal.
        """

    async def close(self) -> None:  # noqa: B027 - concrete and empty on purpose
        """Release any connection this store holds. A no-op by default.

        Deliberately not abstract, for the reason
        `postern_core.auth.revocation`'s `RevocationStoreBase` gives: neither
        backend here holds anything to release, and making every future one
        implement an empty method is how a caller ends up not calling it.
        """
        return None


class InMemoryDeviceKeyStore(DeviceKeyStoreBase):
    """Enrolled keys held in this process, for tests and for `FileDeviceKeyStore`.

    Per replica and lost on restart, which for enrolment data would be a
    deployment defect rather than a degraded mode -- so nothing selects this
    from the environment. It is constructed explicitly, by the file store
    below and by a test that has generated a key pair.
    """

    def __init__(self, keys: dict[str, tuple[EnrolledDeviceKey, ...]] | None = None) -> None:
        self._keys: dict[str, tuple[EnrolledDeviceKey, ...]] = dict(keys or {})

    async def keys_for(self, customer_ref: str) -> tuple[EnrolledDeviceKey, ...]:
        return self._keys.get(customer_ref, ())

    @property
    def enrolled_customers(self) -> int:
        """How many customers carry at least one key. For startup logging."""
        return sum(1 for keys in self._keys.values() if keys)


class FileDeviceKeyStore(DeviceKeyStoreBase):
    """A JSON document on disk, which is the shape an enrolment export renders.

    The same reasoning `postern_core.auth.keys`'s `FileKeySource` carries: a
    file is what a sidecar, an init container or a mounted secret produces,
    and reading it at construction means a misrendered one fails at STARTUP
    rather than at the first approval. Parsing is strict for the same reason
    -- an enrolment record that cannot be read must not silently become a
    customer who cannot approve.

    Format::

        {
          "customers": {
            "cust_7f3a": [
              {"kid": "ios-2026-09", "kty": "OKP", "crv": "Ed25519", "x": "..."}
            ]
          }
        }

    Each entry is an ordinary public JWK plus a ``kid``, so an operator whose
    enrolment system already publishes JWKS documents assembles this by
    concatenation. Top-level keys other than ``customers`` are ignored, so an
    operator may carry their own metadata; ``customers`` itself is REQUIRED,
    so a misspelling of it fails at startup instead of producing a file that
    enrols nobody.

    A ``d`` parameter -- private key material -- is refused outright rather
    than ignored. This file is public-key data by construction; one carrying a
    private half means an enrolment export leaked a device's signing key, and
    a process that starts anyway is a process that will not be looked at.
    """

    def __init__(self, path: Path) -> None:
        self._path = path
        self._keys = InMemoryDeviceKeyStore(_load_enrolment(path))
        if self._keys.enrolled_customers == 0:
            warn_no_enrolled_devices(path)
        else:
            logger.info(
                "device key store loaded from %s: %d customer(s) enrolled",
                path,
                self._keys.enrolled_customers,
            )

    async def keys_for(self, customer_ref: str) -> tuple[EnrolledDeviceKey, ...]:
        return await self._keys.keys_for(customer_ref)


def no_enrolled_devices() -> InMemoryDeviceKeyStore:
    """A store that holds no keys, so every approval refuses. TEST AND LOCAL SEAM.

    Named rather than written as a bare ``InMemoryDeviceKeyStore()`` at each
    site, so that ``grep -rn no_enrolled_devices`` lists every app built in
    this repository that cannot approve anything -- the naming precedent is
    `postern_core.auth.revocation`'s `unchecked_revocation`, which exists so
    that every place the ZT-7 check is deliberately absent is greppable.

    The difference from that precedent is worth stating, because it is the
    whole of decision 2 on this control: ``unchecked_revocation`` returns a
    permissive answer, and this returns a store that refuses everybody. There
    is no seam anywhere in this module that verifies less; the only thing a
    misconfiguration can produce is a service where nobody can approve. That
    is why it warns rather than raises, and why the raise lives at startup in
    ``services/confirm/main.py`` instead.

    Silent on purpose, where `FileDeviceKeyStore` warns: this is chosen in
    code by a test that means it, not by a deployment that got an environment
    variable wrong.
    """
    return InMemoryDeviceKeyStore()


def warn_no_enrolled_devices(path: Path) -> None:
    """Say out loud that the store this process loaded can approve nothing.

    The mechanism and the shape are `postern_core.auth.keys`'s
    ``warn_ephemeral_signing_key``: a ``RuntimeWarning``, unconditional, and
    naming the CONSEQUENCE rather than the state, because "loaded zero
    enrolment records" tells an operator nothing they can act on.

    A warning and not a refusal, for one specific reason: an empty enrolment
    file is the correct state of a deployment on its first day, and the
    service still has to serve ``/.well-known/jwks.json`` and the device grant
    while the enrolment flow is being built. What it must not do is approve a
    payment, and an empty store already guarantees that.
    """
    warnings.warn(
        f"no device is enrolled in {path}: every approval this process receives will be "
        f"refused with 'device_not_enrolled', because verifying an approval signature "
        f"needs the public key of the customer's own phone and this file names none. "
        f"That is fail-closed and it is also a service that cannot move money. Publish "
        f"the enrolled public keys into this file from the enrolment system that holds "
        f"them; see postern_core.auth.device_keys for the format.",
        RuntimeWarning,
        stacklevel=3,
    )


def _load_enrolment(path: Path) -> dict[str, tuple[EnrolledDeviceKey, ...]]:
    """Parse the enrolment document, or raise before the app is built."""
    try:
        raw = json.loads(path.read_bytes())
    except (OSError, ValueError) as exc:
        raise ValueError(
            f"the device key store at {path} could not be read: {type(exc).__name__}. "
            "The confirm service will not start without a readable enrolment document."
        ) from exc

    if not isinstance(raw, dict) or "customers" not in raw:
        raise ValueError(
            f"the device key store at {path} has no 'customers' object. A document "
            "without one enrols nobody, which is indistinguishable at run time from a "
            "misspelled key, so it is refused here instead."
        )
    customers = raw["customers"]
    if not isinstance(customers, dict):
        raise ValueError(f"'customers' in {path} must be an object keyed by customer reference")

    enrolled: dict[str, tuple[EnrolledDeviceKey, ...]] = {}
    for customer_ref, entries in customers.items():
        if not isinstance(customer_ref, str) or not customer_ref:
            raise ValueError(f"{path} carries an enrolment under an empty customer reference")
        if not isinstance(entries, list):
            raise ValueError(f"the enrolment for {customer_ref!r} in {path} is not a list of JWKs")
        if len(entries) > MAX_KEYS_PER_CUSTOMER:
            raise ValueError(
                f"the enrolment for {customer_ref!r} in {path} carries {len(entries)} keys, "
                f"more than MAX_KEYS_PER_CUSTOMER ({MAX_KEYS_PER_CUSTOMER}); every one of "
                "them is tried on every approval."
            )
        keys = tuple(_parse_key(entry, customer_ref=customer_ref, path=path) for entry in entries)
        kids = [key.kid for key in keys]
        if len(set(kids)) != len(kids):
            raise ValueError(
                f"the enrolment for {customer_ref!r} in {path} repeats a kid; a kid names "
                "one device and a duplicate means two records describe the same one."
            )
        enrolled[customer_ref] = keys
    return enrolled


def _parse_key(entry: Any, *, customer_ref: str, path: Path) -> EnrolledDeviceKey:
    """One enrolment record as a key, or raise naming what is wrong with it."""
    if not isinstance(entry, dict):
        raise ValueError(f"an enrolment for {customer_ref!r} in {path} is not a JWK object")
    kid = entry.get("kid")
    if not isinstance(kid, str) or not kid:
        raise ValueError(f"an enrolment for {customer_ref!r} in {path} carries no 'kid'")
    if "d" in entry:
        # Never included in the message: the value would be the private key.
        raise ValueError(
            f"the enrolment {kid!r} for {customer_ref!r} in {path} carries a 'd' parameter, "
            "which is PRIVATE key material. This document holds public keys only. A device "
            "signing key that has reached a file on this host is compromised and must be "
            "de-enrolled rather than loaded."
        )
    if entry.get("kty") != "OKP" or entry.get("crv") != REQUIRED_CURVE:
        raise ValueError(
            f"the enrolment {kid!r} for {customer_ref!r} in {path} is not an OKP "
            f"{REQUIRED_CURVE} key; nothing else is verified here."
        )
    try:
        key = OKPKey.import_key(dict(entry))
    except Exception as exc:
        raise ValueError(
            f"the enrolment {kid!r} for {customer_ref!r} in {path} is not a usable "
            f"{REQUIRED_CURVE} public key: {type(exc).__name__}"
        ) from exc
    if key.is_private:
        # Unreachable while the `d` check above stands; kept because "this
        # object can sign" is the property that actually matters and it is
        # cheaper to assert it than to trust that one spelling of it was the
        # only one.
        raise ValueError(
            f"the enrolment {kid!r} for {customer_ref!r} in {path} imported as a private key"
        )
    return EnrolledDeviceKey(kid=kid, key=key)

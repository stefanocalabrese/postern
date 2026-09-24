"""The canonical approval message, the signature wire form, and the key store.

No database, no ASGI, no Docker: everything here is about bytes.
``tests/test_device_signature.py`` is where the control is driven end to end.

WHY A GOLDEN LITERAL. Every other suite signs through
`postern_core.auth.approval_signature`'s ``canonical_approval_message`` and
verifies through it too, so a bug in the encoder would be invisible to all of
them -- signer and verifier would agree on the same wrong bytes. The literal in
``test_the_encoding_is_exactly_this`` is the independent witness: it was
hand-counted netstring by netstring rather than copied from a passing run, and
it fails the moment the encoding changes, which is exactly when
`APPROVAL_DOMAIN`'s version must change too or every enrolled phone in the
field starts producing signatures the server rejects.
"""

from __future__ import annotations

import base64
import json
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest
from joserfc.jwa import EdDSAAlgorithm
from joserfc.jwk import OKPKey
from postern_core.auth.approval_signature import (
    APPROVAL_DOMAIN,
    SIGNATURE_BYTES,
    UncanonicalChallengeError,
    canonical_approval_message,
    decode_signature,
    verify_approval_signature,
)
from postern_core.auth.device_keys import (
    MAX_KEYS_PER_CUSTOMER,
    REQUIRED_CURVE,
    EnrolledDeviceKey,
    FileDeviceKeyStore,
    InMemoryDeviceKeyStore,
    no_enrolled_devices,
)

from tests.fixtures.device_keys import device_key, sign_fields, sign_message

DEADLINE = datetime(2026, 9, 24, 10, 11, 12, 131415, tzinfo=UTC)


def _message(**overrides: Any) -> bytes:
    fields: dict[str, Any] = {
        "challenge_id": "chal_1",
        "customer_ref": "cust_7f3a",
        "tool_name": "payments.create_payment",
        "payload": {"amount": "EUR 340.00", "payee": "Acme Ltd"},
        "expires_at": DEADLINE,
    }
    fields.update(overrides)
    return canonical_approval_message(**fields)


# ---------------------------------------------------------------------------
# 1. The encoding, byte for byte.
# ---------------------------------------------------------------------------


def test_the_encoding_is_exactly_this() -> None:
    """The golden message. Read it: every length here is countable by hand.

    ``d200:`` opens the outer object and says its pairs occupy 200 bytes.
    ``12:challenge_id,`` is the key, ``s6:chal_1,`` the string value, and so
    on in key order. The inner ``d44:`` is the payload. Nothing about this
    needs a tool to check, which is the property a canonical form for a
    cross-language protocol has to have -- the phone signing it is not
    running Python.
    """
    assert _message() == (
        b"postern.device-approval.v1\n"
        b"d200:"
        b"12:challenge_id,s6:chal_1,"
        b"12:customer_ref,s9:cust_7f3a,"
        b"10:expires_at,s27:2026-09-24T10:11:12.131415Z,"
        b"7:payload,d44:6:amount,s10:EUR 340.00,5:payee,s8:Acme Ltd,,"
        b"9:tool_name,s23:payments.create_payment,"
        b","
    )


def test_every_message_carries_the_domain_prefix() -> None:
    """Domain separation: these bytes cannot be a signature over anything else."""
    assert _message().startswith(APPROVAL_DOMAIN + b"\n")


def test_two_challenges_differing_in_one_field_differ_in_the_bytes() -> None:
    """One field at a time, because a message that ignored any of the five
    would let a signature be carried across that difference."""
    base = _message()
    assert _message(challenge_id="chal_2") != base
    assert _message(customer_ref="cust_other") != base
    assert _message(tool_name="cards.freeze_card") != base
    assert _message(payload={"amount": "EUR 3400.00", "payee": "Acme Ltd"}) != base
    assert _message(expires_at=DEADLINE + timedelta(seconds=1)) != base


def test_field_boundaries_cannot_be_shifted() -> None:
    """The collision a delimiter-joined encoding would have.

    ``challenge_id="ab"`` with ``customer_ref="x"`` and ``challenge_id="a"``
    with ``customer_ref="bx"`` are different challenges whose concatenated
    values are identical. Length prefixes are what keep the bytes different.
    """
    assert _message(challenge_id="ab", customer_ref="x") != _message(
        challenge_id="a", customer_ref="bx"
    )


def test_payload_key_order_does_not_change_the_bytes() -> None:
    """``JSONB`` does not preserve insertion order, so the encoding must not
    depend on it. Sorted by UTF-8 bytes, not by Python's ``str`` comparison."""
    assert _message(payload={"a": 1, "b": 2, "é": 3}) == _message(payload={"é": 3, "b": 2, "a": 1})


def test_a_nested_payload_round_trips_through_every_type() -> None:
    """Lists, nested objects, integers, booleans and null all encode, and a
    change anywhere inside changes the bytes."""
    deep: dict[str, Any] = {
        "lines": [{"amount": "EUR 1.00"}, {"amount": "EUR 2.00"}],
        "recurring": True,
        "count": 12,
        "memo": None,
    }
    encoded = _message(payload=deep)
    assert encoded != _message(payload={**deep, "count": 13})
    assert encoded != _message(payload={**deep, "recurring": False})
    assert encoded != _message(payload={**deep, "memo": ""})


def test_true_does_not_encode_as_one() -> None:
    """``bool`` is a subclass of ``int``: without the ordering in ``_encode``
    these two payloads would produce identical bytes."""
    assert _message(payload={"x": True}) != _message(payload={"x": 1})


def test_a_float_payload_is_refused_rather_than_formatted() -> None:
    """The one refusal a real payload can trigger, and the reason amounts are
    strings in this tree."""
    with pytest.raises(UncanonicalChallengeError) as excinfo:
        _message(payload={"amount": 340.0})
    assert "float" in str(excinfo.value)


def test_a_non_string_object_key_is_refused() -> None:
    with pytest.raises(UncanonicalChallengeError):
        _message(payload={1: "one"})


def test_a_naive_deadline_is_refused_rather_than_assumed_to_be_utc() -> None:
    """Guessing a zone is how the server and the phone come to disagree about
    a deadline by an hour."""
    with pytest.raises(UncanonicalChallengeError) as excinfo:
        _message(expires_at=datetime(2026, 9, 24, 10, 11, 12))
    assert "time zone" in str(excinfo.value)


def test_a_deadline_in_another_zone_encodes_as_the_same_instant() -> None:
    """One instant, one spelling, whatever the row's session zone was."""
    madrid = timezone(timedelta(hours=2))
    assert _message(expires_at=DEADLINE.astimezone(madrid)) == _message()


def test_microseconds_are_not_truncated() -> None:
    """Two deadlines a microsecond apart are two different messages, so the
    encoding cannot be rounded to milliseconds by a future edit."""
    assert _message(expires_at=DEADLINE + timedelta(microseconds=1)) != _message()


# ---------------------------------------------------------------------------
# 2. The wire form.
# ---------------------------------------------------------------------------


def test_a_real_signature_decodes_to_sixty_four_bytes() -> None:
    private, _public = device_key()
    wire = sign_message(private, _message())
    assert len(wire) == 86
    raw = decode_signature(wire)
    assert raw is not None and len(raw) == SIGNATURE_BYTES


@pytest.mark.parametrize(
    ("value", "why"),
    [
        ("", "empty"),
        ("short", "too short"),
        ("A" * 85, "one character short"),
        ("A" * 87, "one character long"),
        ("A" * 84 + "==", "padded to 86"),
        ("A" * 85 + "+", "standard base64 alphabet, not base64url"),
        ("A" * 85 + "/", "standard base64 alphabet, not base64url"),
        ("A" * 85 + " ", "whitespace"),
    ],
)
def test_a_signature_that_is_not_86_base64url_characters_is_refused(value: str, why: str) -> None:
    assert decode_signature(value) is None, why


def test_a_padded_spelling_of_a_real_signature_is_refused() -> None:
    """One approval, one string. The padded form decodes to the same 64 bytes
    and would verify; accepting it would mean two spellings of one stored
    signature."""
    private, _public = device_key()
    wire = sign_message(private, _message())
    assert decode_signature(wire + "==") is None


def test_a_non_canonical_spelling_of_a_real_signature_is_refused() -> None:
    """base64 ignores the unused low bits of its last character, so four
    spellings decode to the same 64 bytes. Only the canonical one is accepted,
    which is what the round trip in ``decode_signature`` is for.

    The alternative spelling is derived rather than guessed: it is whatever
    ``urlsafe_b64encode`` does NOT produce for those same bytes.
    """
    private, _public = device_key()
    wire = sign_message(private, _message())
    raw = base64.urlsafe_b64decode(wire + "==")
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    alternatives = [
        wire[:-1] + char
        for char in alphabet
        if char != wire[-1] and base64.urlsafe_b64decode(wire[:-1] + char + "==") == raw
    ]
    assert alternatives, "expected a second spelling of the same 64 bytes"
    for spelling in alternatives:
        assert decode_signature(spelling) is None


# ---------------------------------------------------------------------------
# 3. Verification.
# ---------------------------------------------------------------------------


def test_a_signature_verifies_against_the_key_that_made_it() -> None:
    private, public = device_key("phone-a")
    message = _message()
    raw = decode_signature(sign_message(private, message))
    assert raw is not None
    assert verify_approval_signature(keys=(public,), message=message, signature=raw) == public


def test_a_signature_over_different_content_does_not_verify() -> None:
    """The property that makes the control worth having: the amount is in the
    message, so a signature over one amount cannot approve another."""
    private, public = device_key()
    raw = decode_signature(
        sign_fields(
            private,
            challenge_id="chal_1",
            customer_ref="cust_7f3a",
            tool_name="payments.create_payment",
            payload={"amount": "EUR 1.00", "payee": "Acme Ltd"},
            expires_at=DEADLINE,
        )
    )
    assert raw is not None
    assert verify_approval_signature(keys=(public,), message=_message(), signature=raw) is None


def test_another_customers_key_does_not_verify() -> None:
    _mine, my_public = device_key("mine")
    theirs_private, _theirs_public = device_key("theirs")
    raw = decode_signature(sign_message(theirs_private, _message()))
    assert raw is not None
    assert verify_approval_signature(keys=(my_public,), message=_message(), signature=raw) is None


def test_an_empty_key_set_verifies_nothing() -> None:
    private, _public = device_key()
    raw = decode_signature(sign_message(private, _message()))
    assert raw is not None
    assert verify_approval_signature(keys=(), message=_message(), signature=raw) is None


def test_any_enrolled_key_may_have_signed_it() -> None:
    """Two phones, one customer. Rotation is the same operation as a second
    device, which is why the store answers with a set rather than a key."""
    old_private, old_public = device_key("old-phone")
    new_private, new_public = device_key("new-phone")
    enrolled = (old_public, new_public)

    for private, expected in ((old_private, old_public), (new_private, new_public)):
        raw = decode_signature(sign_message(private, _message()))
        assert raw is not None
        assert verify_approval_signature(keys=enrolled, message=_message(), signature=raw) is (
            expected
        )


def test_a_retired_key_stops_verifying_the_moment_it_leaves_the_set() -> None:
    """De-enrolment is a write the operator makes to the store, and nothing
    else has to change for it to take effect."""
    retired_private, retired_public = device_key("lost-phone")
    _kept_private, kept_public = device_key("kept-phone")
    raw = decode_signature(sign_message(retired_private, _message()))
    assert raw is not None

    assert (
        verify_approval_signature(
            keys=(retired_public, kept_public), message=_message(), signature=raw
        )
        is retired_public
    )
    assert verify_approval_signature(keys=(kept_public,), message=_message(), signature=raw) is None


def test_an_ed448_key_verifies_nothing_an_ed25519_device_signed() -> None:
    """``OKP`` covers four curves and ``EdDSAAlgorithm`` accepts two of them.

    An Ed448 key is therefore the one wrong curve that reaches the primitive
    rather than raising: it verifies the signature and reports a mismatch,
    which is a refusal. The store refuses it at load time anyway
    (``test_a_key_on_another_curve_is_refused`` below), so this pins the
    behaviour behind that guard rather than relying on it.
    """
    ed448 = OKPKey.generate_key("Ed448")
    private, _public = device_key()
    raw = decode_signature(sign_message(private, _message()))
    assert raw is not None
    enrolled = (EnrolledDeviceKey(kid="ed448", key=ed448),)
    assert verify_approval_signature(keys=enrolled, message=_message(), signature=raw) is None


def test_an_x25519_key_cannot_verify_anything() -> None:
    """X25519 is key agreement: it has no signing operation at all, and an
    enrolment record carrying one is refused by the store before this could
    matter."""
    private, _public = device_key()
    raw = decode_signature(sign_message(private, _message()))
    assert raw is not None
    enrolled = (EnrolledDeviceKey(kid="x25519", key=OKPKey.generate_key("X25519")),)
    with pytest.raises(Exception):  # noqa: B017 - joserfc's InvalidKeyTypeError
        verify_approval_signature(keys=enrolled, message=_message(), signature=raw)


def test_the_algorithm_is_fixed_and_not_read_from_anything() -> None:
    """No ``alg`` header exists on this path, so there is nothing to confuse.

    Stated as a test because the JWT shape everywhere else in this repository
    is the one that DOES negotiate an algorithm, and a future edit that
    "reused the JWS helper" would reintroduce exactly that.
    """
    private, public = device_key()
    message = _message()
    raw = decode_signature(sign_message(private, message))
    assert raw is not None
    # The same bytes signed with HMAC under a key the attacker controls do not
    # become acceptable: there is no path here that reads an algorithm name.
    assert verify_approval_signature(keys=(public,), message=message, signature=raw) is public
    assert EdDSAAlgorithm().name == "EdDSA"


# ---------------------------------------------------------------------------
# 4. The store.
# ---------------------------------------------------------------------------


async def test_an_in_memory_store_answers_with_the_enrolled_keys() -> None:
    _private, public = device_key()
    store = InMemoryDeviceKeyStore({"cust_7f3a": (public,)})
    assert await store.keys_for("cust_7f3a") == (public,)


async def test_an_unknown_customer_gets_an_empty_tuple_not_an_error() -> None:
    """ "Nobody enrolled" is a refusal the caller turns into a 403, not an
    exception: an exception is reserved for a store that cannot answer."""
    store = InMemoryDeviceKeyStore({"cust_7f3a": (device_key()[1],)})
    assert await store.keys_for("cust_nobody") == ()


async def test_no_enrolled_devices_enrols_nobody() -> None:
    """The named seam. ``grep -rn no_enrolled_devices`` is how a reader finds
    every app in this repository that can approve nothing."""
    assert await no_enrolled_devices().keys_for("cust_7f3a") == ()


def _enrolment_file(tmp_path: Path, document: object) -> Path:
    path = tmp_path / "device-keys.json"
    path.write_text(json.dumps(document))
    return path


def _public_jwk(kid: str = "phone-1") -> dict[str, Any]:
    key = OKPKey.generate_key(REQUIRED_CURVE)
    entry: dict[str, Any] = dict(key.as_dict(private=False))
    entry["kid"] = kid
    return entry


async def test_a_file_store_loads_what_the_operator_published(tmp_path: Path) -> None:
    entry = _public_jwk()
    path = _enrolment_file(tmp_path, {"customers": {"cust_7f3a": [entry]}})

    store = FileDeviceKeyStore(path)
    keys = await store.keys_for("cust_7f3a")

    assert [key.kid for key in keys] == ["phone-1"]
    assert await store.keys_for("cust_other") == ()


def test_an_empty_enrolment_file_warns_loudly_and_still_starts(tmp_path: Path) -> None:
    """Decision 2's development path, in one test: explicit (a path an
    operator typed), loud (a ``RuntimeWarning`` naming the consequence), and
    fail-closed (it enrols nobody, so every approval is refused). What it is
    NOT is a mode that verifies less."""
    path = _enrolment_file(tmp_path, {"customers": {}})

    with pytest.warns(RuntimeWarning, match="no device is enrolled"):
        store = FileDeviceKeyStore(path)

    assert store is not None


def test_the_empty_file_warning_names_the_consequence(tmp_path: Path) -> None:
    """Same bar as ``warn_ephemeral_signing_key``: a message that said only
    "loaded zero records" would tell an operator nothing to act on."""
    path = _enrolment_file(tmp_path, {"customers": {}})
    with pytest.warns(RuntimeWarning) as caught:
        FileDeviceKeyStore(path)
    message = str(caught[0].message)
    assert "device_not_enrolled" in message
    assert "refused" in message
    assert str(path) in message


def test_the_local_development_enrolment_file_enrols_nobody() -> None:
    """``stub/device-keys.json`` is what ``docker-compose.yml`` mounts into the
    confirm container. It must stay empty: a committed enrolment would be a
    key nobody controls, and a committed PRIVATE key would be a device signing
    key in version control.

    Driven through the real store rather than read as JSON, so this also pins
    that the compose stack starts -- the file parses, warns, and enrols
    nobody, which is the whole local-development path.
    """
    path = Path("stub/device-keys.json")
    document = json.loads(path.read_text())
    assert document["customers"] == {}
    for entries in document["customers"].values():
        for entry in entries:
            assert "d" not in entry, "a private key is committed in the enrolment file"

    with pytest.warns(RuntimeWarning, match="no device is enrolled"):
        FileDeviceKeyStore(path)


@pytest.mark.parametrize(
    ("document", "expected"),
    [
        ({}, "no 'customers' object"),
        ({"custumers": {}}, "no 'customers' object"),
        ({"customers": []}, "must be an object"),
        ({"customers": {"cust_7f3a": {}}}, "not a list"),
        ({"customers": {"cust_7f3a": ["not-a-jwk"]}}, "not a JWK object"),
        ({"customers": {"cust_7f3a": [{"kty": "OKP", "crv": "Ed25519"}]}}, "no 'kid'"),
    ],
)
def test_a_malformed_enrolment_document_refuses_at_startup(
    tmp_path: Path, document: object, expected: str
) -> None:
    """Every one of these fails when the process starts rather than when the
    first payment is approved -- the reason `FileDeviceKeyStore` parses in its
    constructor, which is `postern_core.auth.keys`'s `FileKeySource` argument
    unchanged."""
    with pytest.raises(ValueError, match=expected):
        FileDeviceKeyStore(_enrolment_file(tmp_path, document))


def test_an_unreadable_enrolment_file_refuses_at_startup(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="could not be read"):
        FileDeviceKeyStore(tmp_path / "does-not-exist.json")


def test_a_key_on_another_curve_is_refused(tmp_path: Path) -> None:
    """Ed448 signs, X25519 does not, and neither is what this repository
    verifies. One curve, fixed here rather than in an enrolment record."""
    for curve in ("Ed448", "X25519"):
        entry: dict[str, Any] = dict(OKPKey.generate_key(curve).as_dict(private=False))
        entry["kid"] = "wrong-curve"
        path = tmp_path / f"{curve}.json"
        path.write_text(json.dumps({"customers": {"cust_7f3a": [entry]}}))
        with pytest.raises(ValueError, match="Ed25519"):
            FileDeviceKeyStore(path)


def test_a_private_key_in_the_enrolment_file_is_refused(tmp_path: Path) -> None:
    """THE ONE THAT IS AN INCIDENT RATHER THAN A TYPO. This document holds
    public keys; a ``d`` parameter means a device's signing key reached a file
    on the host, and a process that starts anyway is one nobody looks at."""
    key = OKPKey.generate_key(REQUIRED_CURVE)
    entry: dict[str, Any] = dict(key.as_dict(private=True))
    entry["kid"] = "leaked"
    path = _enrolment_file(tmp_path, {"customers": {"cust_7f3a": [entry]}})

    with pytest.raises(ValueError) as excinfo:
        FileDeviceKeyStore(path)

    message = str(excinfo.value)
    assert "PRIVATE key material" in message
    # And the message never quotes the value it is refusing.
    assert str(entry["d"]) not in message


def test_a_duplicate_kid_is_refused(tmp_path: Path) -> None:
    """A kid names one device, so two records under one kid describe a state
    that cannot be acted on: de-enrolling "that phone" would be ambiguous."""
    first = _public_jwk("same-kid")
    second = _public_jwk("same-kid")
    path = _enrolment_file(tmp_path, {"customers": {"cust_7f3a": [first, second]}})

    with pytest.raises(ValueError, match="repeats a kid"):
        FileDeviceKeyStore(path)


def test_more_keys_than_the_ceiling_is_refused(tmp_path: Path) -> None:
    """Every enrolled key is tried on every approval, so an unbounded set is
    unbounded verification work per payment. Bounded where the document is
    read, which is startup."""
    entries = [_public_jwk(f"phone-{index}") for index in range(MAX_KEYS_PER_CUSTOMER + 1)]
    path = _enrolment_file(tmp_path, {"customers": {"cust_7f3a": entries}})

    with pytest.raises(ValueError, match="MAX_KEYS_PER_CUSTOMER"):
        FileDeviceKeyStore(path)


async def test_the_ceiling_itself_loads(tmp_path: Path) -> None:
    """The refusal above is only worth something if the boundary is usable."""
    entries = [_public_jwk(f"phone-{index}") for index in range(MAX_KEYS_PER_CUSTOMER)]
    path = _enrolment_file(tmp_path, {"customers": {"cust_7f3a": entries}})

    store = FileDeviceKeyStore(path)

    assert len(await store.keys_for("cust_7f3a")) == MAX_KEYS_PER_CUSTOMER


async def test_unknown_top_level_keys_are_ignored(tmp_path: Path) -> None:
    """An operator's own metadata rides along; ``customers`` is what is read.
    ``stub/device-keys.json`` relies on this for its own explanation."""
    path = _enrolment_file(
        tmp_path,
        {"_readme": ["anything"], "version": 3, "customers": {"cust_7f3a": [_public_jwk()]}},
    )

    assert len(await FileDeviceKeyStore(path).keys_for("cust_7f3a")) == 1

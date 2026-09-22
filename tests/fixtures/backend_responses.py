"""Backend responses carrying values that MUST NOT reach a tool result."""

# Luhn-valid (ISO/IEC 7812-1 Annex B), and that is a property of this
# fixture rather than a detail of it. Until audit finding C-07 this was
# 4111111111114417, whose check digits sum to 45 -- a sixteen-digit string
# no payment network would accept, standing in for a card in every test
# that asserts a card cannot escape. That mattered the moment a checksum
# entered the redaction path: the grouped-PAN gate in `masking.py` is
# Luhn, so an impossible card cannot demonstrate the leak it was being
# used to demonstrate. It is also why this module no longer carries a
# separate `LUHN_PAN` -- with `FULL_PAN` corrected the two were the same
# sixteen digits.
FULL_PAN = "4111111111111111"
FULL_IBAN = "ES9121000418450200051332"
COUNTERPARTY_IBAN = "DE89370400440532013000"

# The same PAN and IBAN written the way a human types one into a memo, and
# the way an attacker writes one to survive a scan that only looks for an
# uninterrupted run. Added alongside the contiguous constants above, never
# instead of them: the contiguous shapes are what `_PAN_IN_TEXT_RE` and
# `_IBAN_IN_TEXT_RE` were built for and must keep catching, and a golden
# test that swapped them for the grouped forms would stop proving that.
GROUPED_PAN = "4111 1111 1111 1111"
HYPHEN_PAN = "4111-1111-1111-1111"
DOTTED_PAN = "4111.1111.1111.1111"
NBSP_PAN = "4111 1111 1111 1111"
# U+00BA MASCULINE ORDINAL INDICATOR, one of the 18 `_LATIN_SCRIPT_EXEMPTIONS`
# members. On a Spanish keyboard, so this reads as ordinary local text.
ORDINAL_PAN = "41111111º11111111"

GROUPED_IBAN = "ES91 2100 0418 4502 0005 1332"
HYPHEN_IBAN = "ES91-2100-0418-4502-0005-1332"
# Lowercase: ISO 13616 IBANs are conventionally rendered uppercase, which is
# exactly why a scan that assumes it misses this one.
LOWERCASE_IBAN = "es9121000418450200051332"
# U+00AA FEMININE ORDINAL INDICATOR, the same bypass class as `ORDINAL_PAN`.
ORDINAL_IBAN = "ES91210004184ª50200051332"

ACCOUNTS = {
    "accounts": [
        {"id": "acc_7f3a", "label": "Joint expenses", "iban": FULL_IBAN},
        {"id": "acc_9b21", "label": "Savings", "iban": "ES2221000418450200051119"},
    ]
}

BALANCE = {
    "account_id": "acc_7f3a",
    "amount": "1200.50",
    "currency": "EUR",
    "as_of": "2026-09-12T10:00:00Z",
}

LEAKY_DESCRIPTION = (
    f"Card {FULL_PAN} purchase, ref {COUNTERPARTY_IBAN}"
    f" grouped {GROUPED_PAN} hyphen {HYPHEN_PAN} dotted {DOTTED_PAN}"
    f" nbsp {NBSP_PAN} ordinal {ORDINAL_PAN}"
    f" iban {GROUPED_IBAN} hyphen {HYPHEN_IBAN}"
    f" lower {LOWERCASE_IBAN} ordinal {ORDINAL_IBAN}"
)

TRANSACTIONS = {
    "transactions": [
        {
            "id": "txn_1",
            "account_id": "acc_7f3a",
            "booked_at": "2026-09-11T08:30:00Z",
            "amount": "-34.20",
            "currency": "EUR",
            "counterparty_name": "Acme Ltd",
            "counterparty_iban": COUNTERPARTY_IBAN,
            "description": LEAKY_DESCRIPTION,
        }
    ]
}

CARDS = {"cards": [{"id": "crd_1", "label": "Debit", "pan": FULL_PAN, "status": "active"}]}

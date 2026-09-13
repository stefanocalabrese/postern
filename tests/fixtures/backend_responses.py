"""Backend responses carrying values that MUST NOT reach a tool result."""

FULL_PAN = "4111111111114417"
FULL_IBAN = "ES9121000418450200051332"
COUNTERPARTY_IBAN = "DE89370400440532013000"

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
            "description": f"Card {FULL_PAN} purchase, ref {COUNTERPARTY_IBAN}",
        }
    ]
}

CARDS = {"cards": [{"id": "crd_1", "label": "Debit", "pan": FULL_PAN, "status": "active"}]}

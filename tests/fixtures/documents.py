"""Document fixtures for the improve loop. Synthetic PII only."""

from __future__ import annotations

from document_sanitizer.improve import DocumentFixture

INVOICE_MALAYSIA = DocumentFixture(
    name="invoice_malaysia",
    description="Malaysian invoice with email, phone, MyKad, and amount",
    mode="confidential",
    text="""\
Invoice #INV-1001
Customer: AHMAD BIN ALI
MyKad: 900101-14-5678
Email: ahmad.demo@example.com.my
Phone: +60123456789
Amount due: RM 1,234.56
GST: 6%
Total: see Amount due
""",
    must_redact=[
        "ahmad.demo@example.com.my",
        "+60123456789",
        "900101-14-5678",
        "AHMAD BIN ALI",
        "RM 1,234.56",
    ],
    safe_to_keep=["Invoice", "GST", "Total", "Customer"],
)

SECRETS_AND_PII = DocumentFixture(
    name="secrets_and_pii",
    description="API key plus email in a config snippet",
    mode="pii",
    text="""\
OPENAI_API_KEY=sk-abcdefghijklmnopqrstuvwxyz123456
contact: ops@contoso.example
password: "hunter2secret"
""",
    must_redact=[
        "sk-abcdefghijklmnopqrstuvwxyz123456",
        "ops@contoso.example",
        "hunter2secret",
    ],
    safe_to_keep=["OPENAI_API_KEY", "contact", "password"],
)

IBAN_AND_CARD = DocumentFixture(
    name="iban_and_card",
    description="IBAN and Luhn-valid card number",
    mode="pii",
    text="""\
IBAN: GB82 WEST 1234 5698 7654 32
Card: 4111 1111 1111 1111
Ref: Invoice
""",
    must_redact=[
        "GB82 WEST 1234 5698 7654 32",
        "4111 1111 1111 1111",
    ],
    safe_to_keep=["IBAN", "Card", "Invoice", "Ref"],
)

STRUCTURAL_LABELS = DocumentFixture(
    name="structural_labels",
    description="Labels that must survive; only values redact",
    mode="pii",
    text="""\
Email: nobody@example.org
Phone: 012-345 6789
MyKad: 880808-08-8888
""",
    must_redact=[
        "nobody@example.org",
        "012-345 6789",
        "880808-08-8888",
    ],
    safe_to_keep=["Email", "Phone", "MyKad"],
)

ALL_FIXTURES: list[DocumentFixture] = [
    INVOICE_MALAYSIA,
    SECRETS_AND_PII,
    IBAN_AND_CARD,
    STRUCTURAL_LABELS,
]

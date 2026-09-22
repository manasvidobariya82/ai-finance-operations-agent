from app import models
from app.pipeline.accounting import build_journal_entry, journal_entry_to_csv


def make_invoice():
    return models.Invoice(
        filename="f.pdf",
        file_path="/tmp/f.pdf",
        vendor_name="Acme Supplies",
        invoice_number="INV-001",
        invoice_date="2026-01-10",
        currency="USD",
        total_amount=108.0,
    )


def test_journal_entry_is_balanced():
    entry = build_journal_entry(make_invoice())
    total_debit = sum(line["debit"] for line in entry["lines"])
    total_credit = sum(line["credit"] for line in entry["lines"])
    assert total_debit == total_credit == 108.0


def test_journal_entry_csv_contains_amount():
    entry = build_journal_entry(make_invoice())
    csv_text = journal_entry_to_csv(entry, invoice_id=1)
    assert "108.0" in csv_text
    assert "Acme Supplies" in csv_text
